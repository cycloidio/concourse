package tsa

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"

	"net/http/httputil"

	"fmt"

	"code.cloudfoundry.org/lager"
	"github.com/concourse/atc"
	"github.com/tedsuo/rata"
)

const (
	ReportContainers      = "report-containers"
	ReportVolumes         = "report-volumes"
	ResourceActionMissing = "resource-type-missing"
)

type WorkerStatus struct {
	ATCEndpoint      *rata.RequestGenerator
	TokenGenerator   TokenGenerator
	ContainerHandles []string
	VolumeHandles    []string
}

func (l *WorkerStatus) WorkerStatus(logger lager.Logger, worker atc.Worker, resourceAction string) error {

	logger.Debug("start")
	defer logger.Debug("end")

	var (
		handlesBytes []byte
		err          error
		request      *http.Request
	)

	switch resourceAction {
	case ReportContainers:
		handlesBytes, err = json.Marshal(l.ContainerHandles)
		if err != nil {
			logger.Error("failed-to-encode-request-body", err)
			return err
		}

		request, err = l.ATCEndpoint.CreateRequest(atc.ReportWorkerContainers, nil, bytes.NewBuffer(handlesBytes))

		if err != nil {
			logger.Error("failed-to-construct-request", err)
			return err
		}
	case ReportVolumes:
		handlesBytes, err = json.Marshal(l.VolumeHandles)
		if err != nil {
			logger.Error("failed-to-encode-request-body", err)
			return err
		}

		request, err = l.ATCEndpoint.CreateRequest(atc.ReportWorkerVolumes, nil, bytes.NewBuffer(handlesBytes))

		if err != nil {
			logger.Error("failed-to-construct-request", err)
			return err
		}
	default:
		return errors.New(ResourceActionMissing)
	}

	if worker.Name == "" {
		logger.Info("empty-worker-name-in-req")
		return fmt.Errorf("empty-worker-name")
	}
	request.Header.Add("Content-Type", "application/json")

	request.URL.RawQuery = url.Values{
		"worker_name": []string{worker.Name},
	}.Encode()

	var jwtToken string
	jwtToken, err = l.TokenGenerator.GenerateSystemToken()

	if err != nil {
		logger.Error("failed-to-generate-token", err)
		return err
	}

	request.Header.Add("Authorization", "Bearer "+jwtToken)

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		logger.Error(fmt.Sprintf("failed-to-%s", resourceAction), err)
		return err
	}

	logger.Debug("atc-response", lager.Data{"response-status": response.StatusCode})

	defer response.Body.Close()

	if response.StatusCode != http.StatusNoContent {
		logger.Error("bad-response", nil, lager.Data{
			"status-code": response.StatusCode,
		})

		b, _ := httputil.DumpResponse(response, true)
		return fmt.Errorf("bad-response (%d): %s", response.StatusCode, string(b))
	}

	logger.Info(fmt.Sprintf("successfully-%s", resourceAction))
	return nil
}
