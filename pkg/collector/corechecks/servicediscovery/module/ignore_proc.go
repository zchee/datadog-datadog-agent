// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

//go:build linux

package module

import (
	"github.com/shirou/gopsutil/v3/process"
)

// ignoreServices is a list of service names that should not be reported as a service.
var ignoreServices = map[string]struct{}{
	"datadog-agent": {},
}

// shouldIgnorePid returns true if service should be ignored
func (s *discovery) shouldIgnorePid(proc *process.Process) bool {
	s.mux.Lock()
	_, found := s.ignorePids[proc.Pid]
	s.mux.Unlock()

	return found
}

// saveIgnoredProc saves the process pid if the service should be ignored
func (s *discovery) saveIgnoredProc(name string, proc *process.Process) {
	s.mux.Lock()
	defer s.mux.Unlock()

	_, found := ignoreServices[name]
	if found {
		s.ignorePids[proc.Pid] = true
	}
}

// cleanIgnoredProc deletes dead PIDs from the ignored processes.
func (s *discovery) cleanIgnoredProc(alivePids map[int32]struct{}) {
	s.mux.Lock()
	defer s.mux.Unlock()

	for pid := range s.ignorePids {
		if _, alive := alivePids[pid]; alive {
			continue
		}

		delete(s.ignorePids, pid)
	}
}
