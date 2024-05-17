// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package hashicorploader

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/DataDog/datadog-agent/comp/core/pid/shared"
	"github.com/hashicorp/go-plugin"
)

func CreateComponent() error {
	// We're a host. Start by launching the plugin process.
	client := plugin.NewClient(&plugin.ClientConfig{
		HandshakeConfig: shared.Handshake,
		Plugins:         shared.PluginMap,
		Cmd:             exec.Command("sh", "-c", os.Getenv("KV_PLUGIN")),
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
	err = kv.Put("Hello", []byte("World"))
	if err != nil {
		return err
	}

	result, err := kv.Get("Hello")
	if err != nil {
		return err
	}
	fmt.Println("-----------------", string(result))
	return nil
}
