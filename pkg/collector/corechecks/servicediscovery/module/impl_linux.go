// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package module

import (
	"fmt"
	"net/http"

	"github.com/DataDog/datadog-agent/cmd/system-probe/api/module"
	sysconfigtypes "github.com/DataDog/datadog-agent/cmd/system-probe/config/types"
	"github.com/DataDog/datadog-agent/cmd/system-probe/utils"
	"github.com/DataDog/datadog-agent/comp/core/telemetry"
	workloadmeta "github.com/DataDog/datadog-agent/comp/core/workloadmeta/def"
	"github.com/DataDog/datadog-agent/pkg/collector/corechecks/servicediscovery/model"
	"github.com/DataDog/datadog-agent/pkg/collector/corechecks/servicediscovery/portlist"
	"github.com/DataDog/datadog-agent/pkg/util/log"
	"github.com/DataDog/datadog-agent/pkg/util/optional"
)

const (
	pathOpenPorts = "/open_ports"
)

// Ensure discovery implements the module.Module interface.
var _ module.Module = &discovery{}

// discovery is an implementation of the Module interface for the discovery module.
type discovery struct {
	portPoller *portlist.Poller
}

// NewDiscoveryModule creates a new discovery system probe module.
func NewDiscoveryModule(*sysconfigtypes.Config, optional.Option[workloadmeta.Component], telemetry.Component) (module.Module, error) {
	poller, err := portlist.NewPoller()
	if err != nil {
		return nil, err
	}
	return &discovery{portPoller: poller}, nil
}

// GetStats returns the stats of the discovery module.
func (s *discovery) GetStats() map[string]interface{} {
	return nil
}

// Register registers the discovery module with the provided HTTP mux.
func (s *discovery) Register(httpMux *module.Router) error {
	httpMux.HandleFunc("/status", s.handleStatusEndpoint)
	httpMux.HandleFunc(pathOpenPorts, s.handleOpenPorts)
	return nil
}

// Close cleans resources used by the discovery module.
// Currently, a no-op.
func (s *discovery) Close() {}

// handleStatusEndpoint is the handler for the /status endpoint.
// Reports the status of the discovery module.
func (s *discovery) handleStatusEndpoint(w http.ResponseWriter, _ *http.Request) {
	_, _ = w.Write([]byte("Discovery Module is running"))
}

func (s *discovery) handleError(w http.ResponseWriter, route string, status int, err error) {
	_ = log.Errorf("failed to handle /discovery/%s (status: %d): %v", route, status, err)
	w.WriteHeader(status)
}

func (s *discovery) handleOpenPorts(w http.ResponseWriter, _ *http.Request) {
	ports, err := s.portPoller.OpenPorts()
	if err != nil {
		s.handleError(w, pathOpenPorts, http.StatusInternalServerError, fmt.Errorf("failed to get open ports: %v", err))
		return
	}

	var portsResp []*model.Port
	for _, p := range ports {
		portsResp = append(portsResp, &model.Port{
			PID:         p.Pid,
			ProcessName: p.Process,
			Port:        int(p.Port),
			Proto:       p.Proto,
		})
	}
	resp := &model.OpenPortsResponse{
		Ports: portsResp,
	}
	utils.WriteAsJSON(w, resp)
}
