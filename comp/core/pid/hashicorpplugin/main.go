// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"github.com/DataDog/datadog-agent/comp/core/pid/shared"
	"github.com/hashicorp/go-plugin"
)

type PidImpl struct {
	pidFilePath string
}

func (pid *PidImpl) Init(pidFilePath string, logger shared.Logger) error {
	pid.pidFilePath = pidFilePath
	logger.Log("PID file path set to: " + pidFilePath)
	return nil
}

func (pid *PidImpl) PIDFilePath() (string, error) {
	return pid.pidFilePath, nil
}

func main() {
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: shared.Handshake,
		Plugins: map[string]plugin.Plugin{
			"pid-plugin": &shared.PidPlugin{Impl: &PidImpl{}},
		},

		// A non-nil value here enables gRPC serving for this plugin...
		GRPCServer: plugin.DefaultGRPCServer,
	})
}
