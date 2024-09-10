// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf

//go:generate $GOPATH/bin/include_headers pkg/collector/corechecks/ebpf/c/runtime/oom-kill-kern.c pkg/ebpf/bytecode/build/runtime/oom-kill.c pkg/ebpf/c
//go:generate $GOPATH/bin/integrity pkg/ebpf/bytecode/build/runtime/oom-kill.c pkg/ebpf/bytecode/runtime/oom-kill.go runtime

// Package oomkill is the system-probe side of the OOM Kill check
package oomkill

import (
	manager "github.com/DataDog/ebpf-manager"

	"github.com/DataDog/datadog-agent/pkg/collector/corechecks/ebpf/probe/oomkill/model"
	"github.com/DataDog/datadog-agent/pkg/ebpf"
	"github.com/DataDog/datadog-agent/pkg/ebpf/maps"
)

// Probe is the eBPF side of the OOM Kill check
type Probe struct {
	m      *manager.Manager
	oomMap *maps.GenericMap[uint64, oomStats]
}

// NewProbe creates a [Probe]
func NewProbe(_ *ebpf.Config) (*Probe, error) {
	return &Probe{}, nil
}

// Close releases all associated resources
func (k *Probe) Close() {}

// GetAndFlush gets the stats
func (k *Probe) GetAndFlush() (results []model.OOMKillStats) {
	return results
}
