// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf

// Package failure contains logic specific to TCP failed connection handling
package failure

import (
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
	releaser    ddsync.PoolReleaser[Conn]
	callback    func(conn *Conn)
	FailedConns *FailedConns
}

// NewFailedConnConsumer creates a new TCPFailedConnConsumer
func NewFailedConnConsumer(releaser ddsync.PoolReleaser[Conn], fc *FailedConns) *TCPFailedConnConsumer {
	return &TCPFailedConnConsumer{
		releaser:    releaser,
		FailedConns: fc,
	}
}

// Callback is a function that can be used as the handler from a perf.EventHandler
func (c *TCPFailedConnConsumer) Callback(failedConn *Conn) {
	failedConnConsumerTelemetry.eventsReceived.Inc()
	c.callback(failedConn)
	c.releaser.Put(failedConn)
}

func (c *TCPFailedConnConsumer) Start(callback func(conn *Conn)) {
	if c == nil {
		return
	}
	c.callback = callback
}

// Stop stops the consumer
func (c *TCPFailedConnConsumer) Stop() {
	if c == nil {
		return
	}
	c.FailedConns.connCloseFlushedCleaner.Stop()
}
