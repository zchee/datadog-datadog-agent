// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build !windows

package util

import (
	"context"
	"fmt"
	"net"
)

var knownPlatform = map[string]string{
	"apm":      "apm_config.debug.port",
	"security": "security_agent.cmd_port",
	"process":  "process_config.cmd_port",
	"core":     "cmd_port",
}

// func getDialContext(config config.Reader) DialContext {
func getDialContext(agentAdresses func() AgentAdresses) DialContext {
	return func(_ context.Context, network string, addr string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return &net.TCPConn{}, err
		}

		var path string

		switch host {
		case CoreCmd:
			path = agentAdresses().CoreAgent.Cmd
		case CoreExpvar:
			path = agentAdresses().CoreAgent.Expvar

		case TraceCmd:
			path = agentAdresses().TraceAgent.Cmd
		case TraceExpvar:
			path = agentAdresses().TraceAgent.Expvar

		case ProcessCmd:
			path = agentAdresses().ProcessAgent.Cmd
		case ProcessExpvar:
			path = agentAdresses().ProcessAgent.Expvar

		case SecurityCmd:
			path = agentAdresses().SecurityAgent.Cmd
		case SecurityExpvar:
			path = agentAdresses().SecurityAgent.Expvar

		case ClusterAgent:
			path = agentAdresses().ClusterAgent.Cmd
		default:
			path = addr
		}

		if path == "" {
			return &net.TCPConn{}, err
		}

		fmt.Printf("receive request for %v", addr)

		return net.Dial("tcp", path)
	}
}
