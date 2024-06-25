// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf

package dns

import (
	"fmt"
	"math"
	"sync/atomic"

	"golang.org/x/net/bpf"

	"github.com/vishvananda/netns"

	manager "github.com/DataDog/ebpf-manager"

	"github.com/DataDog/datadog-agent/comp/core/telemetry"
	ddebpf "github.com/DataDog/datadog-agent/pkg/ebpf"
	"github.com/DataDog/datadog-agent/pkg/network/config"
	"github.com/DataDog/datadog-agent/pkg/network/ebpf/probes"
	filterpkg "github.com/DataDog/datadog-agent/pkg/network/filter"
	"github.com/DataDog/datadog-agent/pkg/security/secl/model"
	"github.com/DataDog/datadog-agent/pkg/util/kernel"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

type dnsMonitor struct {
	*socketFilterSnooper
	p *ebpfProgram
}

type rawPacketDnsMonitor struct {
	*socketFilterSnooper
	rawPacketChan chan *model.Event
	running       atomic.Value
}

// HandlePacket from event
func (m *rawPacketDnsMonitor) HandlePacket(ev *model.Event) {
	if m.running.Load() != true {
		return
	}

	select {
	case m.rawPacketChan <- ev:
		snooperTelemetry.rawPktsReceived.Inc()
	default:
		snooperTelemetry.rawPktsChanErrors.Inc()
	}
}

// NewReverseDNS starts snooping on DNS traffic to allow IP -> domain reverse resolution
func NewReverseDNSRawPacket(cfg *config.Config, _ telemetry.Component) (*rawPacketDnsMonitor, error) {
	ch := make(chan *model.Event, 10000)

	packetSrc := &rawPacketSource{ch: ch}

	snoop, err := newSocketFilterSnooper(cfg, packetSrc)
	if err != nil {
		return nil, err
	}
	m := &rawPacketDnsMonitor{
		socketFilterSnooper: snoop,
		rawPacketChan:       ch,
	}
	m.running.Store(true)

	return m, nil
}

// NewReverseDNS starts snooping on DNS traffic to allow IP -> domain reverse resolution
func NewReverseDNS(cfg *config.Config, _ telemetry.Component) (ReverseDNS, error) {
	currKernelVersion, err := kernel.HostVersion()
	if err != nil {
		// if the platform couldn't be determined, treat it as new kernel case
		log.Warn("could not detect the platform, will use kprobes from kernel version >= 4.1.0")
		currKernelVersion = math.MaxUint32
	}
	pre410Kernel := currKernelVersion < kernel.VersionCode(4, 1, 0)

	var p *ebpfProgram
	var filter *manager.Probe
	var bpfFilter []bpf.RawInstruction

	if pre410Kernel {
		bpfFilter, err = generateBPFFilter(cfg)
		if err != nil {
			return nil, fmt.Errorf("error creating bpf classic filter: %w", err)
		}
	} else {
		p, err = newEBPFProgram(cfg)
		if err != nil {
			return nil, fmt.Errorf("error creating ebpf program: %w", err)
		}

		if err := p.Init(); err != nil {
			return nil, fmt.Errorf("error initializing ebpf programs: %w", err)
		}

		filter, _ = p.GetProbe(manager.ProbeIdentificationPair{EBPFFuncName: probes.SocketDNSFilter, UID: probeUID})
		if filter == nil {
			return nil, fmt.Errorf("error retrieving socket filter")
		}
	}

	// Create the RAW_SOCKET inside the root network namespace
	var (
		packetSrc packetSource
		srcErr    error
		ns        netns.NsHandle
	)
	if ns, err = cfg.GetRootNetNs(); err != nil {
		return nil, err
	}
	defer ns.Close()

	err = kernel.WithNS(ns, func() error {
		packetSrc, srcErr = filterpkg.NewPacketSource(filter, bpfFilter)
		return srcErr
	})
	if err != nil {
		return nil, err
	}

	snoop, err := newSocketFilterSnooper(cfg, packetSrc)
	if err != nil {
		return nil, err
	}
	return &dnsMonitor{
		snoop,
		p,
	}, nil
}

func (m *dnsMonitor) WaitForDomain(domain string) error {
	return m.statKeeper.WaitForDomain(domain)
}

// Start starts the monitor
func (m *dnsMonitor) Start() error {
	if m.p != nil {
		return m.p.Start()
	}
	return nil
}

// Close releases associated resources
func (m *dnsMonitor) Close() {
	m.socketFilterSnooper.Close()
	if m.p != nil {
		ddebpf.RemoveNameMappings(m.p.Manager)
		_ = m.p.Stop(manager.CleanAll)
	}
}

// Close releases associated resources
func (m *rawPacketDnsMonitor) Close() {
	m.socketFilterSnooper.Close()
	m.running.Store(false)
}
