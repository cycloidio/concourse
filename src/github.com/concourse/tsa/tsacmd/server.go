package tsacmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"code.cloudfoundry.org/clock"
	gclient "code.cloudfoundry.org/garden/client"
	gconn "code.cloudfoundry.org/garden/client/connection"
	"code.cloudfoundry.org/lager"
	"github.com/concourse/atc"
	bclient "github.com/concourse/baggageclaim/client"
	"github.com/concourse/tsa"
	"github.com/tedsuo/ifrit"
	"golang.org/x/crypto/ssh"
)

const maxForwards = 2

type registrarSSHServer struct {
	logger            lager.Logger
	logLevel          lager.LogLevel
	atcEndpointPicker tsa.EndpointPicker
	tokenGenerator    tsa.TokenGenerator
	heartbeatInterval time.Duration
	cprInterval       time.Duration
	forwardHost       string
	config            *ssh.ServerConfig
	httpClient        *http.Client
	sessionTeam       *sessionTeam
}

type sessionTeam struct {
	sessionTeams map[string]string
	lock         *sync.RWMutex
}

func (s *sessionTeam) AuthorizeTeam(sessionID, team string) {
	s.lock.Lock()
	defer s.lock.Unlock()

	s.sessionTeams[sessionID] = team
}

func (s *sessionTeam) IsNotAuthorized(sessionID, team string) bool {
	s.lock.RLock()
	defer s.lock.RUnlock()

	t, found := s.sessionTeams[sessionID]

	return found && t != team
}

func (s *sessionTeam) AuthorizedTeamFor(sessionID string) string {
	s.lock.RLock()
	defer s.lock.RUnlock()

	return s.sessionTeams[sessionID]
}

type forwardedTCPIP struct {
	bindAddr  string
	process   ifrit.Process
	boundPort uint32
}

func (server *registrarSSHServer) Serve(listener net.Listener) {
	for {
		c, err := listener.Accept()
		if err != nil {
			if !strings.Contains(err.Error(), "use of closed network connection") {
				server.logger.Error("failed-to-accept", err)
			}

			return
		}

		logger := server.logger.Session("connection", lager.Data{
			"remote": c.RemoteAddr().String(),
		})

		go server.handshake(logger, c)
	}
}

func (server *registrarSSHServer) handshake(logger lager.Logger, netConn net.Conn) {
	conn, chans, reqs, err := ssh.NewServerConn(netConn, server.config)
	if err != nil {
		logger.Info("handshake-failed", lager.Data{"error": err.Error()})
		return
	}

	defer conn.Close()

	forwardedTCPIPs := make(chan forwardedTCPIP, maxForwards)
	go server.handleForwardRequests(logger, conn, reqs, forwardedTCPIPs)

	sessionID := string(conn.SessionID())

	chansGroup := new(sync.WaitGroup)

	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			logger.Info("rejecting-unknown-channel-type", lager.Data{
				"type": newChannel.ChannelType(),
			})

			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}

		channel, requests, err := newChannel.Accept()
		if err != nil {
			logger.Error("failed-to-accept-channel", err)
			return
		}

		chansGroup.Add(1)
		go server.handleChannel(logger.Session("channel"), sessionID, forwardedTCPIPs, chansGroup, channel, requests)
	}

	chansGroup.Wait()
}

func (server *registrarSSHServer) handleChannel(
	logger lager.Logger,
	sessionID string,
	forwardedTCPIPs <-chan forwardedTCPIP,
	chansGroup *sync.WaitGroup,
	channel ssh.Channel,
	requests <-chan *ssh.Request,
) {
	var processes []ifrit.Process

	// ensure processes get cleaned up
	defer func() {
		cleanupLog := logger.Session("cleanup")

		for _, p := range processes {
			cleanupLog.Debug("interrupting")

			p.Signal(os.Interrupt)
		}

		for _, p := range processes {
			err := <-p.Wait()
			if err != nil {
				cleanupLog.Error("process-exited-with-failure", err)
			} else {
				cleanupLog.Debug("process-exited-successfully")
			}
		}
	}()

	defer chansGroup.Done()
	defer channel.Close()

	for req := range requests {
		logger.Info("channel-request", lager.Data{
			"type": req.Type,
		})

		if req.Type != "exec" {
			logger.Info("rejecting")
			req.Reply(false, nil)
			continue
		}

		var request execRequest
		err := ssh.Unmarshal(req.Payload, &request)
		if err != nil {
			logger.Error("malformed-exec-request", err)
			req.Reply(false, nil)
			return
		}

		workerRequest, err := parseRequest(request.Command)
		if err != nil {
			fmt.Fprintf(channel, "invalid command: %s", err)
			req.Reply(false, nil)
			continue
		}

		switch r := workerRequest.(type) {
		case landWorkerRequest:
			logger = logger.Session("land-worker")

			req.Reply(true, nil)

			logger.RegisterSink(lager.NewWriterSink(channel, server.logLevel))
			err := server.landWorker(logger, channel, sessionID)
			if err != nil {
				logger.Error("failed-to-land-worker", err)
				channel.SendRequest("exit-status", false, ssh.Marshal(exitStatusRequest{1}))
				channel.Close()
			} else {
				channel.SendRequest("exit-status", false, ssh.Marshal(exitStatusRequest{0}))
				channel.Close()
			}

		case retireWorkerRequest:
			logger = logger.Session("retire-worker")

			req.Reply(true, nil)

			logger.RegisterSink(lager.NewWriterSink(channel, server.logLevel))
			err := server.retireWorker(logger, channel, sessionID)
			if err != nil {
				logger.Error("failed-to-retire-worker", err)
				channel.SendRequest("exit-status", false, ssh.Marshal(exitStatusRequest{1}))
				channel.Close()
			} else {
				channel.SendRequest("exit-status", false, ssh.Marshal(exitStatusRequest{0}))
				channel.Close()
			}

		case deleteWorkerRequest:
			logger = logger.Session("delete-worker")

			req.Reply(true, nil)

			logger.RegisterSink(lager.NewWriterSink(channel, server.logLevel))
			err := server.deleteWorker(logger, channel, sessionID)
			if err != nil {
				logger.Error("failed-to-delete-worker", err)
				channel.SendRequest("exit-status", false, ssh.Marshal(exitStatusRequest{1}))
				channel.Close()
			} else {
				channel.SendRequest("exit-status", false, ssh.Marshal(exitStatusRequest{0}))
				channel.Close()
			}

		case reportVolumeRequest:
			logger = logger.Session("report-volumes-worker", lager.Data{"num-handles": len(r.handles())})

			req.Reply(true, nil)

			err := server.reportVolumes(logger, channel, sessionID, r.handles())

			if err != nil {
				logger.Error("failed-to-report-volumes", err)
				channel.SendRequest("exit-status", false, ssh.Marshal(exitStatusRequest{1}))
			} else {
				logger.Info("finished-reporting-volumes")
				channel.SendRequest("exit-status", false, ssh.Marshal(exitStatusRequest{0}))
			}

			channel.Close()

		case reportContainerRequest:
			logger = logger.Session("report-containers-worker", lager.Data{"num-handles": len(r.handles())})

			req.Reply(true, nil)

			err := server.reportContainers(logger, channel, sessionID, r.handles())

			if err != nil {
				logger.Error("failed-to-report-containers", err)
				channel.SendRequest("exit-status", false, ssh.Marshal(exitStatusRequest{1}))
			} else {
				logger.Info("finished-reporting-containers")
				channel.SendRequest("exit-status", false, ssh.Marshal(exitStatusRequest{0}))
			}

			channel.Close()

		case sweepContainerRequest:
			logger = logger.Session("sweep-containers-worker")

			req.Reply(true, nil)

			handles, err := server.sweepContainers(logger, channel, sessionID)

			if err != nil {
				logger.Error("failed-to-get-sweep-containers", err)
				channel.SendRequest("exit-status", false, ssh.Marshal(exitStatusRequest{1}))
			} else {
				logger.Info("finished-getting-sweep-containers", lager.Data{"handles": string(handles)})
				bytesNum, err := channel.Write(handles)
				channel.SendRequest("exit-status", false, ssh.Marshal(exitStatusRequest{0}))
				logger.Info("finished-writing-sweeper-containers", lager.Data{"bytes-written": bytesNum, "err": err})
			}

			channel.Close()

		case sweepVolumeRequest:
			logger = logger.Session("sweep-volume-worker")

			req.Reply(true, nil)

			handles, err := server.sweepVolumes(logger, channel, sessionID)

			if err != nil {
				logger.Error("failed-to-get-sweep-volumes", err)
				channel.SendRequest("exit-status", false, ssh.Marshal(exitStatusRequest{1}))
			} else {
				logger.Info("finished-getting-sweep-volumes", lager.Data{"handles": string(handles)})
				bytesNum, err := channel.Write(handles)
				channel.SendRequest("exit-status", false, ssh.Marshal(exitStatusRequest{0}))
				logger.Info("finished-writing-sweeper-volumes", lager.Data{"bytes-written": bytesNum, "err": err})
			}

			channel.Close()

		case registerWorkerRequest:
			logger = logger.Session("register-worker")

			req.Reply(true, nil)

			process, err := server.continuouslyRegisterWorkerDirectly(logger, channel, sessionID)
			if err != nil {
				logger.Error("failed-to-register", err)
				return
			}
			watchForProcessToExit(logger, process, channel)
			processes = append(processes, process)

		case forwardWorkerRequest:
			logger = logger.Session("forward-worker")

			req.Reply(true, nil)

			forwards := map[string]forwardedTCPIP{}

			for i := 0; i < r.expectedForwards(); i++ {
				select {
				case forwarded := <-forwardedTCPIPs:
					logger.Info("forwarded-tcpip", lager.Data{
						"bound-port": forwarded.boundPort,
						"bindAddr":   forwarded.bindAddr,
					})

					processes = append(processes, forwarded.process)

					forwards[forwarded.bindAddr] = forwarded

				case <-time.After(10 * time.Second): // todo better?
					logger.Info("never-forwarded-tcpip")
				}
			}

			logger.Debug("register-forward", lager.Data{"forwardMap": forwards})
			switch len(forwards) {
			case 0:
				fmt.Fprintf(channel, "requested forwarding but no forwards given\n")
				return

			case 1:
				for _, gardenForward := range forwards {
					process, err := server.continuouslyRegisterForwardedWorker(
						logger,
						channel,
						gardenForward.boundPort,
						0,
						sessionID,
					)
					if err != nil {
						logger.Error("failed-to-register", err)
						return
					}
					watchForProcessToExit(logger, process, channel)
					processes = append(processes, process)

					break
				}

			case 2:
				gardenForward, found := forwards[r.gardenAddr]
				if !found {
					fmt.Fprintf(channel, "garden address %s not found in forwards\n", r.gardenAddr)
					return
				}

				baggageclaimForward, found := forwards[r.baggageclaimAddr]
				if !found {
					fmt.Fprintf(channel, "baggageclaim address %s not found in forwards\n", r.gardenAddr)
					return
				}

				process, err := server.continuouslyRegisterForwardedWorker(
					logger,
					channel,
					gardenForward.boundPort,
					baggageclaimForward.boundPort,
					sessionID,
				)
				if err != nil {
					logger.Error("failed-to-register", err)
					return
				}
				watchForProcessToExit(logger, process, channel)
				processes = append(processes, process)
			}
		default:
			logger.Info("invalid-command", lager.Data{
				"command": request.Command,
			})

			req.Reply(false, nil)
		}
	}
}

func (server *registrarSSHServer) continuouslyRegisterWorkerDirectly(
	logger lager.Logger,
	channel ssh.Channel,
	sessionID string,
) (ifrit.Process, error) {
	logger.Info("start")
	defer logger.Info("done")

	var worker atc.Worker
	err := json.NewDecoder(channel).Decode(&worker)
	if err != nil {
		return nil, err
	}

	err = server.validateWorkerTeam(logger, sessionID, worker)
	if err != nil {
		return nil, err
	}

	return server.heartbeatWorker(logger, worker, channel), nil
}

func (server *registrarSSHServer) landWorker(
	logger lager.Logger,
	channel ssh.Channel,
	sessionID string,
) error {
	var worker atc.Worker
	err := json.NewDecoder(channel).Decode(&worker)
	if err != nil {
		return err
	}

	err = server.validateWorkerTeam(logger, sessionID, worker)
	if err != nil {
		return err
	}

	return (&tsa.Lander{
		ATCEndpoint:    server.atcEndpointPicker.Pick(),
		TokenGenerator: server.tokenGenerator,
	}).Land(logger, worker)
}

func (server *registrarSSHServer) retireWorker(
	logger lager.Logger,
	channel ssh.Channel,
	sessionID string,
) error {
	var worker atc.Worker
	err := json.NewDecoder(channel).Decode(&worker)
	if err != nil {
		return err
	}

	err = server.validateWorkerTeam(logger, sessionID, worker)
	if err != nil {
		return err
	}

	return (&tsa.Retirer{
		ATCEndpoint:    server.atcEndpointPicker.Pick(),
		TokenGenerator: server.tokenGenerator,
	}).Retire(logger, worker)
}

func (server *registrarSSHServer) deleteWorker(
	logger lager.Logger,
	channel ssh.Channel,
	sessionID string,
) error {
	var worker atc.Worker
	err := json.NewDecoder(channel).Decode(&worker)
	if err != nil {
		return err
	}

	err = server.validateWorkerTeam(logger, sessionID, worker)
	if err != nil {
		return err
	}

	return (&tsa.Deleter{
		ATCEndpoint:    server.atcEndpointPicker.Pick(),
		TokenGenerator: server.tokenGenerator,
	}).Delete(logger, worker)
}

func (server *registrarSSHServer) reportContainers(
	logger lager.Logger,
	channel ssh.Channel,
	sessionID string,
	handles []string,
) error {
	var worker atc.Worker
	err := json.NewDecoder(channel).Decode(&worker)
	if err != nil {
		return err
	}

	err = server.validateWorkerTeam(logger, sessionID, worker)
	if err != nil {
		return err
	}

	return (&tsa.WorkerStatus{
		ATCEndpoint:      server.atcEndpointPicker.Pick(),
		TokenGenerator:   server.tokenGenerator,
		ContainerHandles: handles,
	}).WorkerStatus(logger, worker, tsa.ReportContainers)
}

func (server *registrarSSHServer) reportVolumes(
	logger lager.Logger,
	channel ssh.Channel,
	sessionID string,
	handles []string,
) error {
	var worker atc.Worker
	err := json.NewDecoder(channel).Decode(&worker)
	if err != nil {
		return err
	}

	err = server.validateWorkerTeam(logger, sessionID, worker)
	if err != nil {
		return err
	}

	return (&tsa.WorkerStatus{
		ATCEndpoint:    server.atcEndpointPicker.Pick(),
		TokenGenerator: server.tokenGenerator,
		VolumeHandles:  handles,
	}).WorkerStatus(logger, worker, tsa.ReportVolumes)
}

func (server *registrarSSHServer) sweepContainers(
	logger lager.Logger,
	channel ssh.Channel,
	sessionID string,
) ([]byte, error) {
	var worker atc.Worker
	err := json.NewDecoder(channel).Decode(&worker)
	if err != nil {
		return nil, err
	}

	err = server.validateWorkerTeam(logger, sessionID, worker)
	if err != nil {
		return nil, err
	}

	return (&tsa.Sweeper{
		ATCEndpoint:    server.atcEndpointPicker.Pick(),
		TokenGenerator: server.tokenGenerator,
	}).Sweep(logger, worker, tsa.SweepContainers)
}

func (server *registrarSSHServer) sweepVolumes(
	logger lager.Logger,
	channel ssh.Channel,
	sessionID string,
) ([]byte, error) {
	var worker atc.Worker
	err := json.NewDecoder(channel).Decode(&worker)
	if err != nil {
		return nil, err
	}

	err = server.validateWorkerTeam(logger, sessionID, worker)
	if err != nil {
		return nil, err
	}

	return (&tsa.Sweeper{
		ATCEndpoint:    server.atcEndpointPicker.Pick(),
		TokenGenerator: server.tokenGenerator,
	}).Sweep(logger, worker, tsa.SweepVolumes)
}

func (server *registrarSSHServer) validateWorkerTeam(
	logger lager.Logger,
	sessionID string,
	worker atc.Worker,
) error {
	if server.sessionTeam.IsNotAuthorized(sessionID, worker.Team) {
		logger.Info("worker-not-allowed", lager.Data{
			"authorized-team": server.sessionTeam.AuthorizedTeamFor(sessionID),
			"request-team":    worker.Team,
		})
		return errors.New("worker-not-allowed-to-team")
	}

	return nil
}

func (server *registrarSSHServer) continuouslyRegisterForwardedWorker(
	logger lager.Logger,
	channel ssh.Channel,
	gardenPort uint32,
	baggageclaimPort uint32,
	sessionID string,
) (ifrit.Process, error) {
	logger.Info("start")
	defer logger.Info("done")

	var worker atc.Worker
	err := json.NewDecoder(channel).Decode(&worker)
	if err != nil {
		return nil, err
	}

	err = server.validateWorkerTeam(logger, sessionID, worker)
	if err != nil {
		return nil, err
	}

	worker.GardenAddr = fmt.Sprintf("%s:%d", server.forwardHost, gardenPort)

	if baggageclaimPort != 0 {
		worker.BaggageclaimURL = fmt.Sprintf("http://%s:%d", server.forwardHost, baggageclaimPort)
	}

	return server.heartbeatWorker(logger, worker, channel), nil
}

func (server *registrarSSHServer) heartbeatWorker(logger lager.Logger, worker atc.Worker, channel ssh.Channel) ifrit.Process {
	return ifrit.Background(tsa.NewHeartbeater(
		logger,
		server.logLevel,
		clock.NewClock(),
		server.heartbeatInterval,
		server.cprInterval,
		gclient.New(gconn.NewWithDialerAndLogger(keepaliveDialerFactory("tcp", worker.GardenAddr), logger.Session("garden-connection"))),
		bclient.NewWithHTTPClient(worker.BaggageclaimURL, &http.Client{
			Transport: &http.Transport{
				DisableKeepAlives:     true,
				ResponseHeaderTimeout: 1 * time.Minute,
			},
		}),
		server.atcEndpointPicker,
		server.tokenGenerator,
		worker,
		channel,
	))
}

func (server *registrarSSHServer) handleForwardRequests(
	logger lager.Logger,
	conn *ssh.ServerConn,
	reqs <-chan *ssh.Request,
	forwardedTCPIPs chan<- forwardedTCPIP,
) {
	var forwardedThings int

	for r := range reqs {
		switch r.Type {
		case "tcpip-forward":
			logger := logger.Session("tcpip-forward")

			forwardedThings++

			if forwardedThings > maxForwards {
				logger.Info("rejecting-extra-forward-request")
				r.Reply(false, nil)
				continue
			}

			var req tcpipForwardRequest
			err := ssh.Unmarshal(r.Payload, &req)
			if err != nil {
				logger.Error("malformed-tcpip-request", err)
				r.Reply(false, nil)
				continue
			}

			listener, err := net.Listen("tcp", "0.0.0.0:0")
			if err != nil {
				logger.Error("failed-to-listen", err)
				r.Reply(false, nil)
				continue
			}

			defer listener.Close()

			bindAddr := net.JoinHostPort(req.BindIP, fmt.Sprintf("%d", req.BindPort))

			logger.Info("forwarding-tcpip", lager.Data{
				"requested-bind-addr": bindAddr,
			})

			_, port, err := net.SplitHostPort(listener.Addr().String())
			if err != nil {
				r.Reply(false, nil)
				continue
			}

			var res tcpipForwardResponse
			_, err = fmt.Sscanf(port, "%d", &res.BoundPort)
			if err != nil {
				r.Reply(false, nil)
				continue
			}

			forPort := req.BindPort
			if forPort == 0 {
				forPort = res.BoundPort
			}

			process := server.forwardTCPIP(logger, conn, listener, req.BindIP, forPort)

			forwardedTCPIPs <- forwardedTCPIP{
				bindAddr:  fmt.Sprintf("%s:%d", req.BindIP, req.BindPort),
				boundPort: res.BoundPort,
				process:   process,
			}

			r.Reply(true, ssh.Marshal(res))

		default:
			// OpenSSH sends keepalive@openssh.com, but there may be other clients;
			// just check for 'keepalive'
			if strings.Contains(r.Type, "keepalive") {
				logger.Info("keepalive", lager.Data{"type": r.Type})
				r.Reply(true, nil)
			} else {
				logger.Info("ignoring-request", lager.Data{"type": r.Type})
				r.Reply(false, nil)
			}
		}
	}
}

func (server *registrarSSHServer) forwardTCPIP(
	logger lager.Logger,
	conn *ssh.ServerConn,
	listener net.Listener,
	forwardIP string,
	forwardPort uint32,
) ifrit.Process {
	return ifrit.Background(ifrit.RunFunc(func(signals <-chan os.Signal, ready chan<- struct{}) error {
		cancel := make(chan struct{})

		interrupted := false
		go func() {
			<-signals

			interrupted = true

			listener.Close()
		}()

		close(ready)

		wg := &sync.WaitGroup{}

		for {
			localConn, err := listener.Accept()
			if err != nil {
				if interrupted {
					logger.Info("interrupted")
					close(cancel)
				} else {
					logger.Error("failed-to-accept", err)
				}

				break
			}
			wg.Add(1)

			go func() {
				defer wg.Done()
				forwardLocalConn(logger.Session("forward-conn"), cancel, localConn, conn, forwardIP, forwardPort)
			}()
		}

		wg.Wait()
		return nil
	}))
}

func forwardLocalConn(logger lager.Logger, cancel <-chan struct{}, localConn net.Conn, conn *ssh.ServerConn, forwardIP string, forwardPort uint32) {
	defer localConn.Close()

	var req forwardTCPIPChannelRequest
	req.ForwardIP = forwardIP
	req.ForwardPort = forwardPort

	host, port, err := net.SplitHostPort(localConn.RemoteAddr().String())
	if err != nil {
		logger.Error("failed-to-split-host-port", err)
		return
	}

	req.OriginIP = host
	_, err = fmt.Sscanf(port, "%d", &req.OriginPort)
	if err != nil {
		logger.Error("failed-to-parse-port", err)
		return
	}

	channel, reqs, err := conn.OpenChannel("forwarded-tcpip", ssh.Marshal(req))
	if err != nil {
		logger.Error("failed-to-open-channel", err)
		return
	}

	defer func() {
		channel.Close()
	}()

	go func() {
		for r := range reqs {
			logger.Info("ignoring-request", lager.Data{
				"type": r.Type,
			})

			r.Reply(false, nil)
		}
	}()

	numPipes := 2
	wait := make(chan struct{}, numPipes)

	pipe := func(to io.WriteCloser, from io.ReadCloser) {
		// if either end breaks, close both ends to ensure they're both unblocked,
		// otherwise io.Copy can block forever if e.g. reading after write end has
		// gone away
		defer to.Close()
		defer from.Close()
		defer func() {
			wait <- struct{}{}
		}()

		io.Copy(to, from)
	}

	go pipe(localConn, channel)
	go pipe(channel, localConn)

	done := 0
dance:
	for {
		select {
		case <-wait:
			done++
			if done == numPipes {
				break dance
			}

			logger.Debug("tcpip-io-complete")
		case <-cancel:
			logger.Info("tcpip-io-interrupted")
			break dance
		}
	}

	return
}

func keepaliveDialerFactory(network string, address string) gconn.DialerFunc {
	return func(string, string) (net.Conn, error) {
		return keepaliveDialer(network, address)
	}
}

func watchForProcessToExit(logger lager.Logger, process ifrit.Process, channel ssh.Channel) {
	logger = logger.Session("wait-for-process")

	go func() {
		err := <-process.Wait()
		if err == nil {
			logger.Debug("exited-successfully")
			channel.SendRequest("exit-status", false, ssh.Marshal(exitStatusRequest{0}))
		} else {
			logger.Error("exited-with-error", err)
		}

		err = channel.Close()
		if err != nil {
			logger.Error("failed-to-close-channel", err)
		} else {
			logger.Debug("closed-channel")
		}
	}()
}
