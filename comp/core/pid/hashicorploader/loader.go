// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package hashicorploader

import (
	"os/exec"

	"github.com/DataDog/datadog-agent/comp/core/pid"
	"github.com/DataDog/datadog-agent/comp/core/pid/pidimpl"
	"github.com/DataDog/datadog-agent/comp/core/pid/shared"
	"github.com/hashicorp/go-plugin"
)

func NewPluginPID(deps pidimpl.Dependencies) (pid.Component, error) {
	// We're a host. Start by launching the plugin process.
	client := plugin.NewClient(&plugin.ClientConfig{
		HandshakeConfig: shared.Handshake,
		Plugins:         shared.PluginMap,
		Cmd:             exec.Command("sh", "-c", "./kv-go-grpc"),
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
	if err := pid.Init(deps.Params.PIDfilePath); err != nil {
		return nil, err
	}

	return pid, nil
}
