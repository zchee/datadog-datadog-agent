// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package module

import (
	"fmt"
	"net/http"
	"sync"

	"github.com/DataDog/datadog-agent/cmd/system-probe/api/module"
	sysconfigtypes "github.com/DataDog/datadog-agent/cmd/system-probe/config/types"
	"github.com/DataDog/datadog-agent/cmd/system-probe/utils"

	//"github.com/DataDog/datadog-agent/pkg/collector/corechecks/servicediscovery"
	//sdconfig "github.com/DataDog/datadog-agent/pkg/collector/corechecks/servicediscovery/config"
	secconfig "github.com/DataDog/datadog-agent/pkg/security/config"
	"github.com/DataDog/datadog-agent/pkg/security/probe"
	"github.com/DataDog/datadog-agent/pkg/util/log"

	"github.com/shirou/gopsutil/v3/process"
)

const (
	pathServices = "/services"
)

// Ensure discovery implements the module.Module interface.
var _ module.Module = &discovery{}

// serviceInfo holds process data that should be cached between calls to the
// endpoint.
type serviceInfo struct {
	generatedName     string
	ddServiceName     string
	ddServiceInjected bool
	//language           language.Language
	//apmInstrumentation apm.Instrumentation
	cmdLine       []string
	startTimeSecs uint64
	cpuTime       uint64
}

// discovery is an implementation of the Module interface for the discovery module.
type discovery struct {
	mux *sync.RWMutex
	// cache maps pids to data that should be cached between calls to the endpoint.
	cache map[int32]*serviceInfo

	// privilegedDetector is used to detect the language of a process.
	//privilegedDetector privileged.LanguageDetector

	// scrubber is used to remove potentially sensitive data from the command line
	//scrubber *procutil.DataScrubber

	// lastGlobalCPUTime stores the total cpu time of the system from the last time
	// the endpoint was called.
	lastGlobalCPUTime uint64
}

// NewDiscoveryModule creates a new discovery system probe module.
func NewDiscoveryModule(_ *sysconfigtypes.Config, _ module.FactoryDependencies) (module.Module, error) {
	return &discovery{
		mux:   &sync.RWMutex{},
		cache: make(map[int32]*serviceInfo),
		//privilegedDetector: privileged.NewLanguageDetector(),
		//scrubber: procutil.NewDefaultDataScrubber(),
	}, nil
}

// GetStats returns the stats of the discovery module.
func (s *discovery) GetStats() map[string]interface{} {
	return nil
}

// Register registers the discovery module with the provided HTTP mux.
func (s *discovery) Register(httpMux *module.Router) error {
	httpMux.HandleFunc("/status", s.handleStatusEndpoint)
	httpMux.HandleFunc(pathServices, utils.WithConcurrencyLimit(utils.DefaultMaxConcurrentRequests, s.handleServices))

	// setup the manager and its probes / perf maps
	if err := s.probe.Setup(); err != nil {
		return fmt.Errorf("failed to setup probe: %w", err)
	}

	// fetch the current state of the system (example: mount points, running processes, ...) so that our user space
	// context is ready when we start the probes
	if err := s.probe.Snapshot(); err != nil {
		return err
	}

	if err := s.probe.Start(); err != nil {
		return err
	}

	return nil
}

// Close cleans resources used by the discovery module.
func (s *discovery) Close() {
	s.mux.Lock()
	defer s.mux.Unlock()
	clear(s.cache)
}

// handleStatusEndpoint is the handler for the /status endpoint.
// Reports the status of the discovery module.
func (s *discovery) handleStatusEndpoint(w http.ResponseWriter, _ *http.Request) {
	_, _ = w.Write([]byte("Discovery Module is running"))
}

// handleServers is the handler for the /services endpoint.
// Returns the list of currently running services.
func (s *discovery) handleServices(w http.ResponseWriter, _ *http.Request) {
	pids, err := process.Pids()
	if err != nil {
		return
	}

	if pids != nil {
		return
	}
}
