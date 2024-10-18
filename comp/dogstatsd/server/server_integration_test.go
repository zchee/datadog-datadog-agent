// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build test

package server

import (
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/DataDog/datadog-agent/comp/dogstatsd/listeners"
)

func TestUDPForward(t *testing.T) {
	cfg := make(map[string]interface{})

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)

	pcHost, pcPort, err := net.SplitHostPort(pc.LocalAddr().String())
	require.NoError(t, err)

	// Setup UDP server to forward to
	cfg["statsd_forward_port"] = pcPort
	cfg["statsd_forward_host"] = pcHost

	// Setup dogstatsd server
	cfg["dogstatsd_port"] = listeners.RandomPortName

	deps := fulfillDepsWithConfigOverride(t, cfg)

	defer pc.Close()

	requireStart(t, deps.Server)

	conn, err := net.Dial("udp", deps.Server.UDPLocalAddr())
	require.NoError(t, err)
	require.NotNil(t, conn)
	defer conn.Close()

	// Check if message is forwarded
	message := []byte("daemon:666|g|#sometag1:somevalue1,sometag2:somevalue2")

	_, err = conn.Write(message)
	require.NoError(t, err, "cannot write to DSD socket")

	_ = pc.SetReadDeadline(time.Now().Add(4 * time.Second))

	buffer := make([]byte, len(message))
	_, _, err = pc.ReadFrom(buffer)
	require.NoError(t, err)

	assert.Equal(t, message, buffer)
}

func TestUDPConn(t *testing.T) {
	cfg := make(map[string]interface{})

	cfg["dogstatsd_port"] = listeners.RandomPortName

	deps := fulfillDepsWithConfigOverride(t, cfg)
	requireStart(t, deps.Server)

	conn, err := net.Dial("udp", deps.Server.UDPLocalAddr())
	require.NoError(t, err, "cannot connect to DSD socket")
	defer conn.Close()

	runConnTest(t, conn, deps)
}

func runConnTest(t *testing.T, conn net.Conn, deps serverDeps) {
	demux := deps.Demultiplexer
	eventOut, serviceOut := demux.GetEventsAndServiceChecksChannels()

	// Test metric
	conn.Write([]byte("daemon:666|g|#foo:bar\niDaemon:777|g|#foo:bar,sometag:tag"))
	samples, timedSamples := demux.WaitForSamples(time.Second * 2)

	assert.Equal(t, 2, len(samples), "expected two metric entries after 2 seconds")
	assert.Equal(t, 0, len(timedSamples), "did not expect any timed metrics")

	m1 := samples[0]
	eMetricName(t, m1, "daemon")
	m2 := samples[1]
	eMetricName(t, m2, "iDaemon")

	// Test servce check
	conn.Write(healthyService)
	select {
	case servL := <-serviceOut:
		assert.Equal(t, 1, len(servL))
		healthyServiceTest.test(t, servL[0])
	}

	// Test event
	conn.Write([]byte("_e{10,10}:test title|test\\ntext|t:warning|d:12345|p:low|h:some.host|k:aggKey|s:source test|#tag1,tag2:test"))
	select {
	case eventL := <-eventOut:
		assert.Equal(t, 1, len(eventL))
	}
}

func TestUDSConn(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "dsd.socket")

	cfg := make(map[string]interface{})
	cfg["dogstatsd_port"] = listeners.RandomPortName
	cfg["dogstatsd_no_aggregation_pipeline"] = true // another test may have turned it off
	cfg["dogstatsd_socket"] = socketPath

	deps := fulfillDepsWithConfigOverride(t, cfg)
	require.True(t, deps.Server.UdsListenerRunning())

	conn, err := net.Dial("unixgram", socketPath)
	require.NoError(t, err, "cannot connect to DSD socket")
	defer conn.Close()

	runConnTest(t, conn, deps)

	s := deps.Server.(*server)
	s.Stop()
	_, err = net.Dial("unixgram", socketPath)
	require.Error(t, err, "UDS listener should be closed")
}
