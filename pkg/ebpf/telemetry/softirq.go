package telemetry

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/DataDog/datadog-agent/pkg/util/log"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/procfs"
)

type NetStatsCollector struct {
	mtx sync.Mutex

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

	lastRead time.Time
}

var StatsCollector *NetStatsCollector

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
		netRxDelta:            make(map[int]uint64),
		netTxDelta:            make(map[int]uint64),
		packetsPerSecondDelta: make(map[int]uint32),
	}

	return StatsCollector
}

func (s *NetStatsCollector) Describe(descs chan<- *prometheus.Desc) {
	if s == nil {
		return
	}

	s.netRxRate.Describe(descs)
	s.netRxAggregateRate.Describe(descs)
	s.netTxRate.Describe(descs)
	s.netTxAggregateRate.Describe(descs)
	s.totalPackets.Describe(descs)
	s.packetsPerSecond.Describe(descs)
	s.packetsPerSecondAggregate.Describe(descs)
}

func (n *NetStatsCollector) Collect(metrics chan<- prometheus.Metric) {
	if n == nil {
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
}
