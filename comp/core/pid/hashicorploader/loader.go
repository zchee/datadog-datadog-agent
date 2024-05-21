// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package hashicorploader

import (
	"fmt"
	"os/exec"

	"github.com/DataDog/datadog-agent/comp/core/pid/shared"
	"github.com/hashicorp/go-plugin"
)

func CreateComponent() error {
	// We're a host. Start by launching the plugin process.
	client := plugin.NewClient(&plugin.ClientConfig{
		HandshakeConfig: shared.Handshake,
		Plugins:         shared.PluginMap,
		Cmd:             exec.Command("sh", "-c", "./kv-go-grpc"),
		AllowedProtocols: []plugin.Protocol{
			plugin.ProtocolNetRPC, plugin.ProtocolGRPC},
	})
	defer client.Kill()

	// Connect via RPC
	rpcClient, err := client.Client()
	if err != nil {
		return err
	}

	// Request the plugin
	raw, err := rpcClient.Dispense(shared.PluginName)
	if err != nil {
		return err
	}

	kv := raw.(shared.Pid)
	if err := kv.Init("Init called"); err != nil {
		return err
	}

	result, err := kv.PIDFilePath()
	if err != nil {
		return err
	}
	fmt.Println("-----------------", string(result))
	return nil
}
