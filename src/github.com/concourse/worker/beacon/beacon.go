package beacon

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"code.cloudfoundry.org/garden"
	"code.cloudfoundry.org/lager"
	"github.com/concourse/atc"
	"github.com/concourse/baggageclaim/client"
	"github.com/concourse/tsa"
)

const (
	gardenForwardAddr       = "0.0.0.0:7777"
	baggageclaimForwardAddr = "0.0.0.0:7788"
	ReaperPort              = "7799"
	reaperAddr              = "0.0.0.0:" + ReaperPort
)

//go:generate counterfeiter . Closeable
type Closeable interface {
	Close() error
}

//go:generate counterfeiter . Client
type Client interface {
	KeepAlive() (<-chan error, chan<- struct{})
	NewSession(stdin io.Reader, stdout io.Writer, stderr io.Writer) (Session, error)
	Listen(n, addr string) (net.Listener, error)
	Proxy(from, to string) error
	Dial() (Closeable, error)
}

//go:generate counterfeiter . Session
type Session interface {
	Wait() error
	// Read out of session
	Close() error
	Start(command string) error
	Output(command string) ([]byte, error)
}

//go:generate counterfeiter . BeaconClient
type BeaconClient interface {
	Register(signals <-chan os.Signal, ready chan<- struct{}) error
	RetireWorker(signals <-chan os.Signal, ready chan<- struct{}) error

	SweepContainers(garden.Client) error
	ReportContainers(garden.Client) error

	SweepVolumes() error
	ReportVolumes() error

	LandWorker(signals <-chan os.Signal, ready chan<- struct{}) error
	DeleteWorker(signals <-chan os.Signal, ready chan<- struct{}) error
	DisableKeepAlive()
}

type Beacon struct {
	Logger           lager.Logger
	Worker           atc.Worker
	Client           Client
	RegistrationMode RegistrationMode
	KeepAlive        bool

	GardenAddr       string
	GardenClient     garden.Client
	BaggageclaimAddr string
}

type RegistrationMode string

const (
	Direct  RegistrationMode = "direct"
	Forward RegistrationMode = "forward"
)

func (beacon *Beacon) Register(signals <-chan os.Signal, ready chan<- struct{}) error {
	beacon.Logger.Debug("registering")
	if beacon.RegistrationMode == Direct {
		return beacon.registerDirect(signals, ready)
	}

	return beacon.registerForwarded(signals, ready)
}

func (beacon *Beacon) registerForwarded(signals <-chan os.Signal, ready chan<- struct{}) error {
	beacon.Logger.Debug("forward-worker")
	return beacon.run(
		"forward-worker "+
			"--garden "+gardenForwardAddr+" "+
			"--baggageclaim "+baggageclaimForwardAddr+" ",
		signals,
		ready,
	)
}

func (beacon *Beacon) registerDirect(signals <-chan os.Signal, ready chan<- struct{}) error {
	beacon.Logger.Debug("register-worker")
	return beacon.run("register-worker", signals, ready)
}

// RetireWorker sends a message via the TSA to retire the worker
func (beacon *Beacon) RetireWorker(signals <-chan os.Signal, ready chan<- struct{}) error {
	beacon.Logger.Debug("retire-worker")
	return beacon.run("retire-worker", signals, ready)
}

func (beacon *Beacon) SweepContainers(gardenClient garden.Client) error {
	command := tsa.SweepContainers
	beacon.Logger.Info("sweep", lager.Data{"cmd": command})

	var handleBytes []byte
	var handles []string
	var err error
	err = beacon.executeCommand(func(sess Session) error {
		handleBytes, err = sess.Output(command)
		if err != nil {
			return beacon.logFailure(command, err)
		}

		err = json.Unmarshal(handleBytes, &handles)
		if err != nil {
			beacon.Logger.Error("unmarshall output failed", err)
			return beacon.logFailure(command, err)
		}
		return nil
	})

	if nil != err {
		return err
	}

	beacon.Logger.Debug("received-handles-to-destroy", lager.Data{"num-handles": len(handles)})
	for _, containerHandle := range handles {
		err := gardenClient.Destroy(containerHandle)
		if err != nil {
			_, ok := err.(garden.ContainerNotFoundError)
			if ok {
				continue
			}
			beacon.Logger.Error("failed-to-delete-container", err, lager.Data{"handle": containerHandle})
		}
		beacon.Logger.Debug("destroyed-container", lager.Data{"handle": containerHandle})
	}

	return nil
}

func (beacon *Beacon) SweepVolumes() error {
	command := tsa.SweepVolumes
	beacon.Logger.Info("sweep", lager.Data{"cmd": command})

	var handleBytes []byte
	var handles []string
	var err error
	err = beacon.executeCommand(func(sess Session) error {
		handleBytes, err = sess.Output(command)
		if err != nil {
			return beacon.logFailure(command, err)
		}

		err = json.Unmarshal(handleBytes, &handles)
		if err != nil {
			beacon.Logger.Error("unmarshall-output-failed", err)
			return beacon.logFailure(command, err)
		}
		return nil
	})

	if nil != err {
		return err
	}

	beacon.Logger.Debug("received-handles-to-destroy", lager.Data{"num-handles": len(handles)})
	var beaconBaggageclaimAddress = beacon.BaggageclaimAddr

	if beaconBaggageclaimAddress == "" {
		beaconBaggageclaimAddress = fmt.Sprint("http://", baggageclaimForwardAddr)
	}
	baggageclaimClient := client.NewWithHTTPClient(
		beaconBaggageclaimAddress, &http.Client{
			Transport: &http.Transport{
				DisableKeepAlives:     true,
				ResponseHeaderTimeout: 1 * time.Minute,
			},
		})

	err = baggageclaimClient.DestroyVolumes(beacon.Logger, handles)
	if err != nil {
		beacon.Logger.Error("failed-to-destroy-handles", err)
		return beacon.logFailure(command, err)
	}

	return err
}

func (beacon *Beacon) ReportContainers(gardenClient garden.Client) error {
	command := tsa.ReportContainers
	beacon.Logger.Info("reporting-containers")
	var err error

	containers, err := gardenClient.Containers(garden.Properties{})
	if err != nil {
		return err
	}

	containerHandles := []string{}

	for _, container := range containers {
		containerHandles = append(containerHandles, container.Handle())
	}

	cmdString := command
	for _, handleStr := range containerHandles {
		cmdString = cmdString + " " + handleStr
	}

	err = beacon.executeCommand(func(sess Session) error {
		_, err = sess.Output(cmdString)
		return err
	})
	if err != nil {
		beacon.Logger.Error("failed-to-execute-cmd", err)
		return beacon.logFailure(command, err)
	}

	beacon.Logger.Debug("sucessfully-reported-container-handles", lager.Data{"num-handles": len(containerHandles)})
	return nil
}

func (beacon *Beacon) ReportVolumes() error {
	command := tsa.ReportVolumes

	var beaconBaggageclaimAddress = beacon.BaggageclaimAddr

	if beaconBaggageclaimAddress == "" {
		beaconBaggageclaimAddress = fmt.Sprint("http://", baggageclaimForwardAddr)
	}

	baggageclaimClient := client.NewWithHTTPClient(
		beaconBaggageclaimAddress, &http.Client{
			Transport: &http.Transport{
				DisableKeepAlives:     true,
				ResponseHeaderTimeout: 1 * time.Minute,
			},
		})

	volumes, err := baggageclaimClient.ListVolumes(beacon.Logger, nil)
	if err != nil {
		return beacon.logFailure(command, err)
	}

	cmdString := command
	for _, volume := range volumes {
		cmdString = cmdString + " " + volume.Handle()
	}

	err = beacon.executeCommand(func(sess Session) error {
		_, err = sess.Output(cmdString)
		return err
	})

	if err != nil {
		beacon.Logger.Error("failed-to-execute-cmd", err)
		return beacon.logFailure(command, err)
	}

	beacon.Logger.Debug("sucessfully-reported-volume-handles", lager.Data{"num-handles": len(volumes)})
	return nil
}

func (beacon *Beacon) LandWorker(signals <-chan os.Signal, ready chan<- struct{}) error {
	beacon.Logger.Debug("land-worker")
	return beacon.run("land-worker", signals, ready)
}

func (beacon *Beacon) DeleteWorker(signals <-chan os.Signal, ready chan<- struct{}) error {
	beacon.Logger.Debug("delete-worker.start")
	return beacon.run("delete-worker", signals, ready)
}

func (beacon *Beacon) DisableKeepAlive() {
	beacon.KeepAlive = false
}

func (beacon *Beacon) run(command string, signals <-chan os.Signal, ready chan<- struct{}) error {
	beacon.Logger.Debug("command-to-run", lager.Data{"cmd": command})

	conn, err := beacon.Client.Dial()
	if err != nil {
		return err
	}
	defer conn.Close()

	var cancelKeepalive chan<- struct{}
	var keepaliveFailed <-chan error

	if beacon.KeepAlive {
		keepaliveFailed, cancelKeepalive = beacon.Client.KeepAlive()
	}

	workerPayload, err := json.Marshal(beacon.Worker)
	if err != nil {
		return err
	}

	sess, err := beacon.Client.NewSession(
		bytes.NewBuffer(workerPayload),
		os.Stdout,
		os.Stderr,
	)

	if err != nil {
		return fmt.Errorf("failed to create session: %s", err)
	}

	defer sess.Close()
	err = sess.Start(command)
	if err != nil {
		return err
	}

	bcURL, err := url.Parse(beacon.Worker.BaggageclaimURL)
	if err != nil {
		return fmt.Errorf("failed to parse baggageclaim url: %s", err)
	}

	var gardenForwardAddrRemote = beacon.Worker.GardenAddr
	var bcForwardAddrRemote = bcURL.Host

	if beacon.GardenAddr != "" {
		gardenForwardAddrRemote = beacon.GardenAddr

		if beacon.BaggageclaimAddr != "" {
			bcForwardAddrRemote = beacon.BaggageclaimAddr
		}
	}

	beacon.Logger.Debug("ssh-forward-config", lager.Data{
		"gardenForwardAddrRemote": gardenForwardAddrRemote,
		"bcForwardAddrRemote":     bcForwardAddrRemote,
	})
	beacon.Client.Proxy(gardenForwardAddr, gardenForwardAddrRemote)
	beacon.Client.Proxy(baggageclaimForwardAddr, bcForwardAddrRemote)

	close(ready)

	exited := make(chan error, 1)

	go func() {
		exited <- sess.Wait()
	}()

	select {
	case <-signals:
		if beacon.KeepAlive {
			close(cancelKeepalive)
		}
		sess.Close()
		<-exited

		// don't bother waiting for keepalive

		return nil
	case err := <-exited:
		if err != nil {
			beacon.Logger.Error("failed-waiting-on-remote-command", err)
		}
		return err
	case err := <-keepaliveFailed:
		beacon.Logger.Error("failed-to-keep-alive", err)
		return err
	}
}

func (beacon *Beacon) executeCommand(command func(Session) error) error {
	conn, err := beacon.Client.Dial()
	if err != nil {
		return err
	}
	defer conn.Close()

	workerPayload, err := json.Marshal(beacon.Worker)
	if err != nil {
		return err
	}

	sess, err := beacon.Client.NewSession(
		bytes.NewBuffer(workerPayload),
		nil,
		os.Stderr,
	)
	if err != nil {
		return fmt.Errorf("failed to create session: %s", err)
	}

	defer sess.Close()

	return command(sess)
}

func (beacon *Beacon) logFailure(command string, err error) error {
	beacon.Logger.Error(fmt.Sprintf("failed-to-%s", command), err)
	return err
}
