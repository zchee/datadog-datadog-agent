// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package hashicorploader

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/hashicorp/go-plugin"
	"github.com/hashicorp/go-plugin/examples/grpc/shared"
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
	raw, err := rpcClient.Dispense("kv_grpc")
	if err != nil {
		return err
	}

	// We should have a KV store now! This feels like a normal interface
	// implementation but is in fact over an RPC connection.
	kv := raw.(shared.KV)
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
