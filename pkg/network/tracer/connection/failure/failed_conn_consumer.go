// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf

// Package failure contains logic specific to TCP failed connection handling
package failure

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"

	netebpf "github.com/DataDog/datadog-agent/pkg/network/ebpf"
	"github.com/DataDog/datadog-agent/pkg/telemetry"
	ddsync "github.com/DataDog/datadog-agent/pkg/util/sync"
)

const failedConnConsumerModuleName = "network_tracer__ebpf"

// Telemetry
var failedConnConsumerTelemetry = struct {
	eventsReceived telemetry.Counter
}{
	telemetry.NewCounter(failedConnConsumerModuleName, "failed_conn_polling_received", []string{}, "Counter measuring the number of failed connections received"),
}

// TCPFailedConnConsumer consumes failed connection events from the kernel
type TCPFailedConnConsumer struct {
	dataChan <-chan *netebpf.FailedConn
	releaser ddsync.PoolReleaser[netebpf.FailedConn]

	once        sync.Once
	closed      chan struct{}
	FailedConns *FailedConns

	tm prometheus.Collector
}

// NewFailedConnConsumer creates a new TCPFailedConnConsumer
func NewFailedConnConsumer(callbackCh <-chan *netebpf.FailedConn, releaser ddsync.PoolReleaser[netebpf.FailedConn], fc *FailedConns) *TCPFailedConnConsumer {
	cons := &TCPFailedConnConsumer{
		releaser:    releaser,
		dataChan:    callbackCh,
		closed:      make(chan struct{}),
		FailedConns: fc,
		tm: prometheus.NewGaugeFunc(
			prometheus.GaugeOpts{
				Subsystem: failedConnConsumerModuleName,
				Name:      "failed_conn_chan_len",
				Help:      "gauge tracking length of failed connections channel",
			},
			func() float64 {
				return float64(len(callbackCh))
			},
		),
	}
	telemetry.GetCompatComponent().RegisterCollector(cons.tm)
	return cons
}

// Stop stops the consumer
func (c *TCPFailedConnConsumer) Stop() {
	if c == nil {
		return
	}
	c.once.Do(func() {
		close(c.closed)
		telemetry.GetCompatComponent().UnregisterCollector(c.tm)
	})
	c.FailedConns.mapCleaner.Stop()
}

// Start starts the consumer
func (c *TCPFailedConnConsumer) Start() {
	if c == nil {
		return
	}

	go func() {
		for {
			select {
			case <-c.closed:
				return
			case failedConn, ok := <-c.dataChan:
				if !ok {
					return
				}
				failedConnConsumerTelemetry.eventsReceived.Inc()
				c.FailedConns.upsertConn(failedConn)
				c.releaser.Put(failedConn)
			}
		}
	}()
}
