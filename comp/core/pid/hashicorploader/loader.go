// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package hashicorploader

import (
	"os/exec"

	"github.com/DataDog/datadog-agent/comp/core/log"
	"github.com/DataDog/datadog-agent/comp/core/pid"
	"github.com/DataDog/datadog-agent/comp/core/pid/pidimpl"
	"github.com/DataDog/datadog-agent/comp/core/pid/shared"
	"github.com/DataDog/datadog-agent/pkg/util/fxutil"
	"github.com/hashicorp/go-plugin"
	"go.uber.org/fx"
)

// Module defines the fx options for this component.
func Module() fxutil.Module {
	return fxutil.Component(
		fx.Provide(newPluginPID),
	)
}

func newPluginPID(deps pidimpl.Dependencies) (pid.Component, error) {
	// We're a host. Start by launching the plugin process.
	client := plugin.NewClient(&plugin.ClientConfig{
		HandshakeConfig: shared.Handshake,
		Plugins:         shared.PluginMap,
		Cmd:             exec.Command("sh", "-c", "./comp/core/pid/kv-go-grpc"),
		AllowedProtocols: []plugin.Protocol{
			plugin.ProtocolNetRPC, plugin.ProtocolGRPC},
	})
	//defer client.Kill()

	// Connect via RPC
	rpcClient, err := client.Client()
	if err != nil {
		return nil, err
	}

	// Request the plugin
	raw, err := rpcClient.Dispense(shared.PluginName)
	if err != nil {
		return nil, err
	}

	pid := raw.(shared.Pid)
	if err := pid.Init(deps.Params.PIDfilePath, &Logger{component: deps.Log}); err != nil {
		return nil, err
	}
	return pid, nil
}

type Logger struct {
	component log.Component
}

func (l *Logger) Log(message string) error {
	l.component.Info("COMPONENT LOG", message)
	return nil
}
