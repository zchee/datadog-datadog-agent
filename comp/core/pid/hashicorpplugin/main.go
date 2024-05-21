// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"fmt"

	"github.com/DataDog/datadog-agent/comp/core/pid"
	"github.com/DataDog/datadog-agent/comp/core/pid/pidimpl"
	"github.com/DataDog/datadog-agent/comp/core/pid/shared"
	"github.com/hashicorp/go-plugin"
)

type PidImpl struct {
	component pid.Component
}

type LoggerWrapper struct {
	logger shared.Logger
}

func (LoggerWrapper) Trace(v ...interface{})                      {}
func (LoggerWrapper) Tracef(format string, params ...interface{}) {}
func (LoggerWrapper) Debug(v ...interface{})                      {}
func (LoggerWrapper) Debugf(format string, params ...interface{}) {}
func (LoggerWrapper) Info(v ...interface{})                       {}
func (l LoggerWrapper) Infof(format string, params ...interface{}) {
	l.logger.Log("INFOF: " + fmt.Sprintf(format, params...))
}
func (LoggerWrapper) Warn(v ...interface{}) error                      { return nil }
func (LoggerWrapper) Warnf(format string, params ...interface{}) error { return nil }
func (LoggerWrapper) Error(v ...interface{}) error                     { return nil }
func (l LoggerWrapper) Errorf(format string, params ...interface{}) error {
	l.logger.Log("Errorf: " + fmt.Sprintf(format, params...))
	return nil
}
func (LoggerWrapper) Critical(v ...interface{}) error                      { return nil }
func (LoggerWrapper) Criticalf(format string, params ...interface{}) error { return nil }
func (LoggerWrapper) Flush()                                               {}

func (pid *PidImpl) Init(pidFilePath string, logger shared.Logger) error {

	c, err := pidimpl.NewPIDWithoutLifecycle(pidimpl.Params{PIDfilePath: pidFilePath}, LoggerWrapper{logger: logger})
	pid.component = c
	return err
}

func (pid *PidImpl) PIDFilePath() (string, error) {
	return pid.PIDFilePath()
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
