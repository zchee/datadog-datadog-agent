// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf

package ebpf

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/DataDog/datadog-agent/pkg/ebpf/bytecode"
	"github.com/DataDog/datadog-agent/pkg/util/kernel"
	"github.com/DataDog/datadog-agent/pkg/util/log"
	manager "github.com/DataDog/ebpf-manager"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/procfs"
)

// NetStatsCollector implements the prometheus Collector interface for exposing
// network interface related metrics
type NetStatsCollector struct {
	mtx         sync.Mutex
	initialized bool

	netRxRate          *prometheus.GaugeVec
	netRxDelta         map[int]uint64
	netTxRate          *prometheus.GaugeVec
	netTxDelta         map[int]uint64
	netRxAggregateRate *prometheus.GaugeVec
	netTxAggregateRate *prometheus.GaugeVec

	totalPackets              *prometheus.CounterVec
	packetsPerSecond          *prometheus.GaugeVec
	packetsPerSecondDelta     map[int]uint32
	packetsPerSecondAggregate *prometheus.GaugeVec
	packetsPerIRQ             *prometheus.GaugeVec
	maxPacketsProcessedPerIrq []uint64

	objects                *netStatsBpfObjects
	links                  []link.Link
	packetsProcessedPerIrq []PPIRQ

	lastRead time.Time
}

type netStatsBpfPrograms struct {
	RawTpSoftirqEntry *ebpf.Program `ebpf:"raw_tracepoint__irq__softirq_entry"`
	RawTpSoftirqExit  *ebpf.Program `ebpf:"raw_tracepoint__irq__softirq_exit"`
}

type netStatsBpfMaps struct {
	PacketsPerIrq *ebpf.Map `ebpf:"packets_per_irq"`
}

type netStatsBpfObjects struct {
	netStatsBpfPrograms
	netStatsBpfMaps
}

var StatsCollector *NetStatsCollector

const (
	softIrqBpfObjectFile = "bytecode/build/co-re/softirq.o"
)

// NewNetStatsCollector create a new NetStatsCollector
func NewNetStatsCollector() *NetStatsCollector {
	StatsCollector = &NetStatsCollector{
		netRxRate: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Subsystem: "ebpf__netstats",
				Name:      "_netrx",
				Help:      "gauge tracking the NET_RX softirq rate",
			},
			[]string{"cpu"},
		),
		netRxAggregateRate: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Subsystem: "ebpf__netstats",
				Name:      "_netrx_aggregate",
				Help:      "gauge tracking the NET_RX softirq rate, aggregated across all cpus",
			},
			[]string{"num_cpus"},
		),
		netTxRate: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Subsystem: "ebpf__netstats",
				Name:      "_nettx",
				Help:      "gauge tracking the NET_TX softirq rate",
			},
			[]string{"cpu"},
		),
		netTxAggregateRate: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Subsystem: "ebpf__netstats",
				Name:      "_nettx_aggregate",
				Help:      "gauge tracking the NET_TX softirq rate aggregated across all cpus",
			},
			[]string{"num_cpus"},
		),
		totalPackets: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Subsystem: "ebpf__netstats",
				Name:      "_total",
				Help:      "counter tracking total packets received on each cpu",
			},
			[]string{"num_cpus"},
		),
		packetsPerSecond: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Subsystem: "ebpf__netstats",
				Name:      "_pps",
				Help:      "gauge tracking packets per second recieved on each cpu",
			},
			[]string{"cpu"},
		),
		packetsPerSecondAggregate: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Subsystem: "ebpf__netstats",
				Name:      "_pps_aggregate",
				Help:      "gauge tracking packets per second recieved on each cpu",
			},
			[]string{"num_cpus"},
		),
		packetsPerIRQ: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Subsystem: "ebpf__netstats",
				Name:      "_max_ppirq",
				Help:      "gauge tracking the maximum packets processed per irq recorded",
			},
			[]string{"cpu"},
		),
		netRxDelta:            make(map[int]uint64),
		netTxDelta:            make(map[int]uint64),
		packetsPerSecondDelta: make(map[int]uint32),
	}

	return StatsCollector
}

// Describe implements prometheus.Collector.Describe
func (s *NetStatsCollector) Describe(descs chan<- *prometheus.Desc) {
	if s == nil {
		return
	}
	if !s.initialized {
		return
	}

	s.netRxRate.Describe(descs)
	s.netRxAggregateRate.Describe(descs)
	s.netTxRate.Describe(descs)
	s.netTxAggregateRate.Describe(descs)
	s.totalPackets.Describe(descs)
	s.packetsPerSecond.Describe(descs)
	s.packetsPerSecondAggregate.Describe(descs)
	s.packetsPerIRQ.Describe(descs)
}

// Collect implements prometheus.Collector.Collect
func (n *NetStatsCollector) Collect(metrics chan<- prometheus.Metric) {
	if n == nil {
		return
	}

	if !n.initialized {
		return
	}

	n.mtx.Lock()
	defer n.mtx.Unlock()

	var fs procfs.FS
	var err error
	if _, statErr := os.Stat("/host"); os.IsNotExist(statErr) {
		fs, err = procfs.NewDefaultFS()
		if err != nil {
			log.Infof("unable to open procfs: %v", err)
			return
		}
	} else {
		fs, err = procfs.NewFS("/host")
		if err != nil {
			log.Infof("unable to open procfs mounted at /host: %v", err)
			return
		}
	}

	softnetStats, err := fs.NetSoftnetStat()
	if err != nil {
		log.Infof("unable to read softnet stats: %v", err)
		return
	}

	softirqStats, err := fs.Softirqs()
	if err != nil {
		log.Infof("unable to read softirq stats: %v", err)
		return
	}

	now := time.Now()
	elapsed := now.Sub(n.lastRead).Seconds()

	var totalPackets float64
	for cpu, s := range softnetStats {
		last := n.packetsPerSecondDelta[cpu]
		n.packetsPerSecondDelta[cpu] = s.Processed

		diff := float64(s.Processed - last)
		if last < s.Processed {
			totalPackets += diff
			n.packetsPerSecond.WithLabelValues(fmt.Sprintf("%d", cpu)).Set(diff / elapsed)
		}
	}
	n.totalPackets.WithLabelValues(fmt.Sprintf("%d", len(softnetStats))).Add(totalPackets)
	n.packetsPerSecondAggregate.WithLabelValues(fmt.Sprintf("%d", len(softnetStats))).Set(totalPackets / elapsed)

	var netRxAggregate float64
	for cpu, netrx := range softirqStats.NetRx {
		last := n.netRxDelta[cpu]
		n.netRxDelta[cpu] = netrx

		if last < netrx {
			diff := float64(netrx - last)
			n.netRxRate.WithLabelValues(fmt.Sprintf("%d", cpu)).Set(diff / elapsed)
			netRxAggregate += diff
		}
	}
	n.netRxAggregateRate.WithLabelValues(fmt.Sprintf("%d", len(softirqStats.NetRx))).Set(netRxAggregate / elapsed)

	var netTxAggregate float64
	for cpu, nettx := range softirqStats.NetTx {
		last := n.netTxDelta[cpu]
		n.netTxDelta[cpu] = nettx

		if last < nettx {
			diff := float64(nettx - last)
			n.netTxRate.WithLabelValues(fmt.Sprintf("%d", cpu)).Set(diff / elapsed)
			netTxAggregate += diff
		}
	}
	n.netTxAggregateRate.WithLabelValues(fmt.Sprintf("%d", len(softirqStats.NetTx))).Set(netTxAggregate / elapsed)

	n.lastRead = now

	var key uint32
	key = 0
	if err := n.objects.PacketsPerIrq.Lookup(&key, n.packetsProcessedPerIrq); err != nil {
		log.Errorf("failed to lookup packets processed per irq: %v", err)
		return
	}

	for i, m := range n.packetsProcessedPerIrq {
		if m.Max_packets_processed > n.maxPacketsProcessedPerIrq[i] {
			n.maxPacketsProcessedPerIrq[i] = m.Max_packets_processed
			n.packetsPerIRQ.WithLabelValues(fmt.Sprintf("%d", i)).Set(float64(m.Max_packets_processed))
		}
	}

	n.netRxRate.Collect(metrics)
	n.netTxRate.Collect(metrics)
	n.netRxAggregateRate.Collect(metrics)
	n.netTxAggregateRate.Collect(metrics)
	n.totalPackets.Collect(metrics)
	n.packetsPerSecond.Collect(metrics)
	n.packetsPerSecondAggregate.Collect(metrics)
	n.packetsPerIRQ.Collect(metrics)
}

// Initialize initializes the ebpf program to collect packets per irq
func (n *NetStatsCollector) Initialize() error {
	if n == nil {
		return nil
	}

	n.mtx.Lock()
	defer n.mtx.Unlock()

	cpus, err := kernel.PossibleCPUs()
	if err != nil {
		return fmt.Errorf("unable to get possible cpus: %w", err)
	}
	n.packetsProcessedPerIrq = make([]PPIRQ, cpus)
	n.maxPacketsProcessedPerIrq = make([]uint64, cpus)

	kaddrs, err := getKernelSymbolsAddressesWithKallsymsIterator("softnet_data", "__per_cpu_offset")
	if err != nil {
		return fmt.Errorf("unable to fetch kernel symbol addresses: %w", err)
	}

	n.objects = new(netStatsBpfObjects)
	if err := LoadCOREAsset(softIrqBpfObjectFile, func(bc bytecode.AssetReader, managerOptions manager.Options) error {
		collectionSpec, err := ebpf.LoadCollectionSpecFromReader(bc)
		if err != nil {
			return fmt.Errorf("failed to load collection spec: %w", err)
		}

		constants := map[string]interface{}{
			"softnet_stats_pcpu": kaddrs["softnet_data"],
			"__per_cpu_offset":   kaddrs["__per_cpu_offset"],
		}
		if err := collectionSpec.RewriteConstants(constants); err != nil {
			return fmt.Errorf("failed to rewrite contant: %w", err)
		}

		opts := ebpf.CollectionOptions{
			Programs: ebpf.ProgramOptions{
				LogLevel:    ebpf.LogLevelBranch,
				KernelTypes: managerOptions.VerifierOptions.Programs.KernelTypes,
			},
		}

		if err := collectionSpec.LoadAndAssign(n.objects, &opts); err != nil {
			var ve *ebpf.VerifierError
			if errors.As(err, &ve) {
				return fmt.Errorf("verfier error loading collection: %s\n%+v", err, ve)
			}
			return fmt.Errorf("failed to load objects: %w", err)
		}

		return nil
	}); err != nil {
		return err
	}

	rawtpSoftirqEntry, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "softirq_entry",
		Program: n.objects.RawTpSoftirqEntry,
	})
	if err != nil {
		return fmt.Errorf("failed to attach raw tracepoint: %w", err)
	}
	n.links = append(n.links, rawtpSoftirqEntry)

	rawtpSoftirqExit, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "softirq_exit",
		Program: n.objects.RawTpSoftirqExit,
	})
	if err != nil {
		return fmt.Errorf("failed to attach raw tracepoint: %w", err)
	}
	n.links = append(n.links, rawtpSoftirqExit)

	log.Info("net stats collector initialized")
	n.initialized = true
	return nil
}

// Close all resources
func (n *NetStatsCollector) Close() {
	for _, ebpfLink := range n.links {
		ebpfLink.Close()
	}

	n.objects.RawTpSoftirqEntry.Close()
	n.objects.RawTpSoftirqExit.Close()
}
