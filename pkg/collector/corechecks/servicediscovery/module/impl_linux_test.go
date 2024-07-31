// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux

package module

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"testing"
	"time"

	"net/http/httptest"

	gorillamux "github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"

	"github.com/DataDog/datadog-agent/cmd/system-probe/api/module"
	"github.com/DataDog/datadog-agent/cmd/system-probe/config"
	"github.com/DataDog/datadog-agent/cmd/system-probe/config/types"
	workloadmetacomp "github.com/DataDog/datadog-agent/comp/core/workloadmeta/def"
	"github.com/DataDog/datadog-agent/pkg/collector/corechecks/servicediscovery/model"
	"github.com/DataDog/datadog-agent/pkg/util/optional"
	"github.com/stretchr/testify/require"
)

func setupDiscoveryModule(t *testing.T) string {
	t.Helper()

	wmeta := optional.NewNoneOption[workloadmetacomp.Component]()
	mux := gorillamux.NewRouter()
	cfg := &types.Config{
		Enabled: true,
		EnabledModules: map[types.ModuleName]struct{}{
			config.DiscoveryModule: {},
		},
	}
	m := module.Factory{
		Name:             config.DiscoveryModule,
		ConfigNamespaces: []string{"discovery"},
		Fn:               NewDiscoveryModule,
		NeedsEBPF: func() bool {
			return false
		},
	}
	err := module.Register(cfg, mux, []module.Factory{m}, wmeta, nil)
	require.NoError(t, err)

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

func startServerAndGetPort(t *testing.T, modURL string) *model.Port {
	t.Helper()

	// start a process listening at some port
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = ln.Close()
	})
	addr := ln.Addr().(*net.TCPAddr)

	req, err := http.NewRequest("GET", modURL+"/discovery/open_ports", nil)
	require.NoError(t, err)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	res := &model.OpenPortsResponse{}
	err = json.NewDecoder(resp.Body).Decode(res)
	require.NoError(t, err)
	require.NotEmpty(t, res)

	for _, p := range res.Ports {
		if p.Port == addr.Port {
			return p
		}
	}
	return nil
}

func TestDiscoveryModule_OpenPorts(t *testing.T) {
	url := setupDiscoveryModule(t)

	port := startServerAndGetPort(t, url)
	require.NotNil(t, port, "could not find http server port")
	assert.Equal(t, "tcp", port.Proto)

	// should be able to get this info since it's a child process, and it will be owned by the current user
	assert.NotEmpty(t, port.ProcessName)
	assert.NotEmpty(t, port.PID)
}

func TestDiscoveryModule_GetProc(t *testing.T) {
	url := setupDiscoveryModule(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	cmd := exec.CommandContext(ctx, "sleep", "1000")
	cmd.Dir = "/tmp/"
	cmd.Env = append(cmd.Env, "DD_SERVICE=foobar")
	cmd.Env = append(cmd.Env, "DD_SERVICE_INVALID=ignored")
	cmd.Env = append(cmd.Env, "OTHER_VARIABLE=other")
	cmd.Env = append(cmd.Env, "JAVA_OPTIONS=quux")
	err := cmd.Start()
	assert.NoError(t, err)
	t.Cleanup(func() {
		cancel()
		cmd.Wait()
	})

	pid := cmd.Process.Pid
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/discovery/procs/%d", url, pid), nil)
	require.NoError(t, err)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	res := &model.GetProcResponse{}
	err = json.NewDecoder(resp.Body).Decode(res)
	require.NoError(t, err)
	require.NotNil(t, res)

	assert.Equal(t, res.Proc.CWD, "/tmp")
	assert.Contains(t, res.Proc.Environ, "DD_SERVICE=foobar")
	assert.NotContains(t, res.Proc.Environ, "DD_SERVICE_INVALID=ignored")
	assert.NotContains(t, res.Proc.Environ, "OTHER_VARIABLE=other")
	assert.Contains(t, res.Proc.Environ, "JAVA_OPTIONS=quux")
}
