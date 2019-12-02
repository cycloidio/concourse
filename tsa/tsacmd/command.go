package tsacmd

import (
	"bytes"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	yaml "gopkg.in/yaml.v2"
	"io/ioutil"

	"os/signal"
	"syscall"

	"code.cloudfoundry.org/lager"
	"github.com/concourse/concourse/atc"
	"github.com/concourse/concourse/tsa"
	"github.com/concourse/flag"
	"github.com/tedsuo/ifrit"
	"github.com/tedsuo/ifrit/grouper"
	"github.com/tedsuo/ifrit/http_server"
	"github.com/tedsuo/ifrit/sigmon"
	"golang.org/x/crypto/ssh"
)

type TSACommand struct {
	Logger flag.Lager

	BindIP      flag.IP `long:"bind-ip"   default:"0.0.0.0" description:"IP address on which to listen for SSH."`
	PeerAddress string  `long:"peer-address" default:"127.0.0.1" description:"Network address of this web node, reachable by other web nodes. Used for forwarded worker addresses."`
	BindPort    uint16  `long:"bind-port" default:"2222"    description:"Port on which to listen for SSH."`

	DebugBindIP   flag.IP `long:"debug-bind-ip"   default:"127.0.0.1" description:"IP address on which to listen for the pprof debugger endpoints."`
	DebugBindPort uint16  `long:"debug-bind-port" default:"2221"      description:"Port on which to listen for the pprof debugger endpoints."`

	HostKey                *flag.PrivateKey               `long:"host-key"        required:"true" description:"Path to private key to use for the SSH server."`
	AuthorizedKeys         flag.AuthorizedKeys            `long:"authorized-keys" description:"Path to file containing keys to authorize, in SSH authorized_keys format (one public key per line)."`
	TeamAuthorizedKeys     map[string]flag.AuthorizedKeys `long:"team-authorized-keys" value-name:"NAME:PATH" description:"Path to file containing keys to authorize, in SSH authorized_keys format (one public key per line)."`
	TeamAuthorizedKeysFile flag.File                      `long:"team-authorized-keys-file" description:"Path to file containing keys to authorize, in SSH authorized_keys yaml format."`

	ATCURLs []flag.URL `long:"atc-url" required:"true" description:"ATC API endpoints to which workers will be registered."`

	SessionSigningKey *flag.PrivateKey `long:"session-signing-key" required:"true" description:"Path to private key to use when signing tokens in reqests to the ATC during registration."`

	HeartbeatInterval time.Duration `long:"heartbeat-interval" default:"30s" description:"interval on which to heartbeat workers to the ATC"`

	ClusterName    string `long:"cluster-name" description:"A name for this Concourse cluster, to be displayed on the dashboard page."`
	LogClusterName bool   `long:"log-cluster-name" description:"Log cluster name."`
}

type TeamAuthKeys struct {
	Team     string
	AuthKeys []ssh.PublicKey
}

type yamlTeamAuthorizedKey struct {
	Team string   `yaml:"team"`
	Keys []string `yaml:"ssh_keys,flow"`
}

func (cmd *TSACommand) Execute(args []string) error {
	runner, err := cmd.Runner(args)
	if err != nil {
		return err
	}

	tsaServerMember := grouper.Member{
		Name:   "tsa-server",
		Runner: sigmon.New(runner),
	}

	tsaDebugMember := grouper.Member{
		Name: "debug-server",
		Runner: http_server.New(
			cmd.debugBindAddr(),
			http.DefaultServeMux,
		)}

	members := []grouper.Member{
		tsaDebugMember,
		tsaServerMember,
	}

	group := grouper.NewParallel(os.Interrupt, members)
	return <-ifrit.Invoke(group).Wait()
}

func (cmd *TSACommand) Runner(args []string) (ifrit.Runner, error) {
	logger, _ := cmd.constructLogger()

	atcEndpointPicker := tsa.NewRandomATCEndpointPicker(cmd.ATCURLs)

	teamAuthorizedKeys, err := cmd.loadTeamAuthorizedKeys()
	if err != nil {
		return nil, fmt.Errorf("failed to load team authorized keys: %s", err)
	}

	if len(cmd.AuthorizedKeys.Keys)+len(cmd.TeamAuthorizedKeys) == 0 {
		logger.Info("starting-tsa-without-authorized-keys")
	}

	sessionAuthTeam := &sessionTeam{
		sessionTeams: make(map[string]string),
		lock:         &sync.RWMutex{},
	}

	config, err := cmd.configureSSHServer(sessionAuthTeam, cmd.AuthorizedKeys.Keys, teamAuthorizedKeys)
	if err != nil {
		return nil, fmt.Errorf("failed to configure SSH server: %s", err)
	}

	listenAddr := fmt.Sprintf("%s:%d", cmd.BindIP, cmd.BindPort)

	if cmd.SessionSigningKey == nil {
		return nil, fmt.Errorf("missing session signing key")
	}

	tokenGenerator := tsa.NewTokenGenerator(cmd.SessionSigningKey.PrivateKey)

	server := &server{
		logger:            logger,
		heartbeatInterval: cmd.HeartbeatInterval,
		cprInterval:       1 * time.Second,
		atcEndpointPicker: atcEndpointPicker,
		tokenGenerator:    tokenGenerator,
		forwardHost:       cmd.PeerAddress,
		config:            config,
		httpClient:        http.DefaultClient,
		sessionTeam:       sessionAuthTeam,
	}
	// Starts a goroutine that his purpose is to basically listen to the
	// SIGUSR1 syscall to then reload the config.
	// For now it only reload the TSACommand.AuthorizedKeys but any
	// other configuration could be added
	go func() {
		for {

			// Set up channel on which to send signal notifications.
			// We must use a buffered channel or risk missing the signal
			// if we're not ready to receive when the signal is sent.
			c := make(chan os.Signal, 1)
			signal.Notify(c, syscall.SIGUSR1)

			// Block until a signal is received.
			_ = <-c

			logger.Info("reloading-config")

			err := cmd.AuthorizedKeys.Reload()
			if err != nil {
				logger.Error("failed to reload authorized keys file : %s", err)
				continue
			}

			// TOOD : need only if reload patch on file. unless not needed
			err = cmd.TeamAuthorizedKeysFile.Reload()
			if err != nil {
				logger.Error("failed to reload the team authorized keys file : %s", err)
				continue
			}

			teamAuthorizedKeys, err = cmd.loadTeamAuthorizedKeys()
			if err != nil {
				logger.Error("failed to load team authorized keys : %s", err)
				continue
			}

			// compute again the config so it's updated
			config, err := cmd.configureSSHServer(sessionAuthTeam, cmd.AuthorizedKeys.Keys, teamAuthorizedKeys)
			if err != nil {
				logger.Error("failed to configure SSH server: %s", err)
				continue
			}

			server.config = config
		}
	}()

	return serverRunner{logger, server, listenAddr}, nil
}

func (cmd *TSACommand) constructLogger() (lager.Logger, *lager.ReconfigurableSink) {
	logger, reconfigurableSink := cmd.Logger.Logger("tsa")
	if cmd.LogClusterName {
		logger = logger.WithData(lager.Data{
			"cluster": cmd.ClusterName,
		})
	}

	return logger, reconfigurableSink
}

func (cmd *TSACommand) loadTeamAuthorizedKeys() ([]TeamAuthKeys, error) {
	var teamKeys []TeamAuthKeys

	for teamName, keys := range cmd.TeamAuthorizedKeys {
		teamKeys = append(teamKeys, TeamAuthKeys{
			Team:     teamName,
			AuthKeys: keys.Keys,
		})
	}

	if cmd.TeamAuthorizedKeysFile != "" {
		logger, _ := cmd.constructLogger()
		var rawTeamAuthorizedKeys []yamlTeamAuthorizedKey

		authorizedKeysBytes, err := ioutil.ReadFile(cmd.TeamAuthorizedKeysFile.Path())
		if err != nil {
			return nil, fmt.Errorf("failed to read yaml authorized keys file: %s", err)
		}
		err = yaml.Unmarshal([]byte(authorizedKeysBytes), &rawTeamAuthorizedKeys)
		if err != nil {
			return nil, fmt.Errorf("failed to parse yaml authorized keys file: %s", err)
		}

		for _, t := range rawTeamAuthorizedKeys {
			var teamAuthorizedKeys []ssh.PublicKey
			for _, k := range t.Keys {
				key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(k))
				if err != nil {
					logger.Error("load-team-authorized-keys-parse", fmt.Errorf("Invalid format, ignoring (%s): %s", k, err.Error()))
					continue
				}
				logger.Info("load-team-authorized-keys-loaded", lager.Data{"team": t.Team, "key": k})
				teamAuthorizedKeys = append(teamAuthorizedKeys, key)
			}
			teamKeys = append(teamKeys, TeamAuthKeys{Team: t.Team, AuthKeys: teamAuthorizedKeys})
		}
	}

	return teamKeys, nil
}

func (cmd *TSACommand) configureSSHServer(sessionAuthTeam *sessionTeam, authorizedKeys []ssh.PublicKey, teamAuthorizedKeys []TeamAuthKeys) (*ssh.ServerConfig, error) {
	certChecker := &ssh.CertChecker{
		IsUserAuthority: func(key ssh.PublicKey) bool {
			return false
		},

		IsHostAuthority: func(key ssh.PublicKey, address string) bool {
			return false
		},

		UserKeyFallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			for _, k := range authorizedKeys {
				if bytes.Equal(k.Marshal(), key.Marshal()) {
					return nil, nil
				}
			}

			for _, teamKeys := range teamAuthorizedKeys {
				for _, k := range teamKeys.AuthKeys {
					if bytes.Equal(k.Marshal(), key.Marshal()) {
						sessionAuthTeam.AuthorizeTeam(string(conn.SessionID()), teamKeys.Team)
						return nil, nil
					}
				}
			}

			return nil, fmt.Errorf("unknown public key")
		},
	}

	config := &ssh.ServerConfig{
		Config: atc.DefaultSSHConfig(),
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			return certChecker.Authenticate(conn, key)
		},
	}

	signer, err := ssh.NewSignerFromKey(cmd.HostKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create signer from host key: %s", err)
	}

	config.AddHostKey(signer)

	return config, nil
}

func (cmd *TSACommand) debugBindAddr() string {
	return fmt.Sprintf("%s:%d", cmd.DebugBindIP, cmd.DebugBindPort)
}
