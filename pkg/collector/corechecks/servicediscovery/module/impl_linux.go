// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package module

import (
	"fmt"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/DataDog/datadog-agent/cmd/system-probe/api/module"
	sysconfigtypes "github.com/DataDog/datadog-agent/cmd/system-probe/config/types"
	"github.com/DataDog/datadog-agent/cmd/system-probe/utils"
	"github.com/DataDog/datadog-agent/comp/core/telemetry"
	workloadmeta "github.com/DataDog/datadog-agent/comp/core/workloadmeta/def"
	"github.com/DataDog/datadog-agent/pkg/collector/corechecks/servicediscovery/model"
	"github.com/DataDog/datadog-agent/pkg/collector/corechecks/servicediscovery/portlist"
	"github.com/DataDog/datadog-agent/pkg/util/log"
	"github.com/DataDog/datadog-agent/pkg/util/optional"
	"github.com/gorilla/mux"
	"github.com/prometheus/procfs"
)

const (
	pathOpenPorts = "/open_ports"
	pathGetProc   = "/procs/{pid}"
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
	httpMux.HandleFunc(pathGetProc, s.handleGetProc)
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

var allowedEnvironmentVariables = map[string]struct{}{
	"PATH":                     {},
	"PWD":                      {},
	"GUNICORN_CMD_ARGS":        {},
	"WSGI_APP":                 {},
	"DD_SERVICE":               {},
	"DD_TAGS":                  {},
	"DD_INJECTION_ENABLED":     {},
	"SPRING_APPLICATION_NAME":  {},
	"SPRING_CONFIG_LOCATIONS":  {},
	"SPRING_CONFIG_NAME":       {},
	"SPRING_PROFILES_ACTIVE":   {},
	"CORECLR_PROFILER_PATH":    {},
	"CORECLR_ENABLE_PROFILING": {},
	"JAVA_TOOL_OPTIONS":        {},
	"_JAVA_OPTIONS":            {},
	"JDK_JAVA_OPTIONS":         {},
	"JAVA_OPTIONS":             {},
	"CATALINA_OPTS":            {},
	"JDPA_OPTS":                {},
	"VIRTUAL_ENV":              {},
}

func filterEnv(in []string) (out []string) {
	for _, env := range in {
		split := strings.SplitN(env, "=", 2)
		if len(split) != 2 {
			continue
		}

		name := split[0]
		if _, ok := allowedEnvironmentVariables[name]; ok {
			out = append(out, env)
		}
	}
	return
}

func (s *discovery) handleGetProc(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	pidStr := vars["pid"]
	pid, err := strconv.ParseUint(pidStr, 10, 32)
	if err != nil {
		s.handleError(w, pathGetProc, http.StatusBadRequest, fmt.Errorf("failed to convert pid to integer: %v", err))
		return
	}

	if _, err := os.Stat(path.Join(procfs.DefaultMountPoint, pidStr)); os.IsNotExist(err) {
		s.handleError(w, pathGetProc, http.StatusNotFound, fmt.Errorf("/proc/{pid} does not exist: %v", err))
		return
	}
	proc, err := procfs.NewProc(int(pid))
	if err != nil {
		s.handleError(w, pathGetProc, http.StatusInternalServerError, fmt.Errorf("failed to read procfs: %v", err))
		return
	}
	env, err := proc.Environ()
	if err != nil {
		s.handleError(w, pathGetProc, http.StatusInternalServerError, fmt.Errorf("failed to read /proc/{pid}/environ: %v", err))
		return
	}
	cwd, err := proc.Cwd()
	if err != nil {
		s.handleError(w, pathGetProc, http.StatusInternalServerError, fmt.Errorf("failed to read /proc/{pid}/cwd: %v", err))
		return
	}

	resp := &model.GetProcResponse{
		Proc: &model.Proc{
			PID:     int(pid),
			Environ: filterEnv(env),
			CWD:     cwd,
		},
	}
	utils.WriteAsJSON(w, resp)
}
