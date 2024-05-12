// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2022-present Datadog, Inc.

//go:build linux_bpf

package usm

import (
	"github.com/cilium/ebpf"
	"io"

	manager "github.com/DataDog/ebpf-manager"

	"github.com/DataDog/datadog-agent/pkg/network/config"
	"github.com/DataDog/datadog-agent/pkg/network/protocols"
	"github.com/DataDog/datadog-agent/pkg/network/usm/buildmode"
)

type dummyProg struct{}

var dummySpec = &protocols.ProtocolSpec{
	Factory: newDummyProgram,
}

func newDummyProgram(*config.Config) (protocols.Protocol, error) {
	return &dummyProg{}, nil
}

// Name return the program's name.
func (p *dummyProg) Name() string {
	return "dummy"
}

// ConfigureOptions changes map attributes to the given options.
func (p *dummyProg) ConfigureOptions(*manager.Manager, *manager.Options) {}

// PreStart subscribes to the exec events to inject the java agent.
func (p *dummyProg) PreStart(*manager.Manager) error {
	return nil
}

// PostStart is a no-op.
func (p *dummyProg) PostStart(*manager.Manager) error {
	return nil
}

// Stop unsubscribes from the exec events.
func (p *dummyProg) Stop(*manager.Manager) {}

// DumpMaps is a no-op.
func (p *dummyProg) DumpMaps(io.Writer, string, *ebpf.Map) {}

// GetStats is a no-op.
func (p *dummyProg) GetStats() *protocols.ProtocolStats {
	return nil
}

// IsBuildModeSupported returns always true, as java tls module is supported by all modes.
func (*dummyProg) IsBuildModeSupported(buildmode.Type) bool {
	return true
}
