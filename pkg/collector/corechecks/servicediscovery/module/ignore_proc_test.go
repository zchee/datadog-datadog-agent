// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

//go:build linux

package module

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/DataDog/datadog-agent/pkg/util/kernel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestShouldIgnoreProc check cases of ignored and non-ignored services
func TestShouldIgnoreProc(t *testing.T) {
	testCases := []struct {
		name   string
		comm   string
		envs   string
		ignore bool
	}{
		{
			name:   "should ignore datadog agent",
			comm:   "agent",
			envs:   "DD_SERVICE=datadog-agent",
			ignore: true,
		},
		{
			name:   "should not ignore dummy process",
			comm:   "dummy",
			envs:   "DD_SERVICE=dummy",
			ignore: false,
		},
	}

	serverBin := buildTestBin(t)
	serverDir := filepath.Dir(serverBin)
	discovery := newDiscovery()
	require.NotEmpty(t, discovery)

	discoveryCtx := parsingContext{
		procRoot:  kernel.ProcFSRoot(),
		netNsInfo: make(map[uint32]*namespaceInfo),
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(func() { cancel() })

			makeAlias(t, test.comm, serverBin)
			bin := filepath.Join(serverDir, test.comm)
			cmd := exec.CommandContext(ctx, bin)
			cmd.Env = append(os.Environ(), test.envs)
			err := cmd.Start()
			require.NoError(t, err)

			require.EventuallyWithT(t, func(collect *assert.CollectT) {
				// find service name
				discovery.getService(discoveryCtx, int32(cmd.Process.Pid))

				// check ignored service
				proc, err := customNewProcess(int32(cmd.Process.Pid))
				require.NoError(t, err)

				ignore := discovery.shouldIgnorePid(proc)
				require.Equal(t, test.ignore, ignore)
			}, 30*time.Second, 100*time.Millisecond)
		})
	}
}
