// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

// Package pidimpl writes the current PID to a file, ensuring that the file
package pidimpl

import (
	"context"
	"os"

	"go.uber.org/fx"

	"github.com/DataDog/datadog-agent/comp/core/log"
	"github.com/DataDog/datadog-agent/comp/core/pid"
	"github.com/DataDog/datadog-agent/pkg/pidfile"
	"github.com/DataDog/datadog-agent/pkg/util/fxutil"
)

// Module defines the fx options for this component.
func Module() fxutil.Module {
	return fxutil.Component(
		fx.Provide(NewPID),
	)
}

// Params are the input parameters for the component.
type Params struct {
	PIDfilePath string
}

// NewParams returns a new Params with the given values.
func NewParams(pidfilePath string) Params {
	return Params{
		PIDfilePath: pidfilePath,
	}
}

type Dependencies struct {
	fx.In
	Lc     fx.Lifecycle
	Log    log.Component
	Params Params
}

type pidImpl struct {
	pidFilePath string
}

func (pid pidImpl) PIDFilePath() (string, error) {
	return pid.pidFilePath, nil
}

func NewPID(deps Dependencies) (pid.Component, error) {
	comp, err := NewPIDWithoutLifecycle(deps.Params, deps.Log)
	if err != nil {
		return nil, err
	}
	deps.Lc.Append(fx.Hook{OnStop: comp.OnStop})

	return pidImpl{}, nil
}

func NewPIDWithoutLifecycle(params Params, log log.Component) (pidImpl, error) {
	pidfilePath := params.PIDfilePath
	log.Infof("NewPIDWithoutLifecycle: pidfilePath: %s", pidfilePath)
	if pidfilePath != "" {
		err := pidfile.WritePID(pidfilePath)
		if err != nil {
			return pidImpl{}, log.Errorf("Error while writing PID file, exiting: %v", err)
		}
		log.Infof("pid '%d' written to pid file '%s'", os.Getpid(), pidfilePath)
	}
	return pidImpl{}, nil
}

func (p pidImpl) OnStop(_ context.Context) error {
	_ = os.Remove(p.pidFilePath)
	return nil
}
