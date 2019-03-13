package retire

import (
	"os"

	"code.cloudfoundry.org/lager"
	"github.com/concourse/atc"
	"github.com/concourse/worker"
	"github.com/concourse/worker/beacon"
	"github.com/concourse/worker/tsa"
	"github.com/tedsuo/ifrit"
)

type RetireWorkerCommand struct {
	TSA tsa.Config `group:"TSA Configuration" namespace:"tsa" required:"true"`

	WorkerName string `long:"name" required:"true" description:"The name of the worker you wish to retire."`
}

func (cmd *RetireWorkerCommand) Execute(args []string) error {
	logger := lager.NewLogger("retire-worker")
	logger.RegisterSink(lager.NewWriterSink(os.Stdout, lager.DEBUG))

	retireWorkerRunner := cmd.retireWorkerRunner(logger)

	return <-ifrit.Invoke(retireWorkerRunner).Wait()
}

func (cmd *RetireWorkerCommand) retireWorkerRunner(logger lager.Logger) ifrit.Runner {
	beacon := worker.NewBeacon(
		logger,
		atc.Worker{
			Name: cmd.WorkerName,
		},
		beacon.Config{
			TSAConfig: cmd.TSA,
		},
	)

	return ifrit.RunFunc(beacon.RetireWorker)
}
