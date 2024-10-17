// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build test

package server

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/DataDog/datadog-agent/comp/dogstatsd/listeners"
)

// Ryan - The unit test way to do this is to abstract the net.Dial call and the listener creation calls
// to factories, the mocks of which can be sent in via test. That seems like a bit heavier of an
// overhaul than the ticket necessarily expects. Alternatives that don't require production code change
// revolve around pulling the input packet array directly from the first instantiated listener, which is a bit
// fragile. Note that if the mac problem is indeed a network layer oops, then an alteration to production code is almost required.
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

func TestE2EParsing(t *testing.T) {
	cfg := make(map[string]interface{})

	cfg["dogstatsd_port"] = listeners.RandomPortName

	deps := fulfillDepsWithConfigOverride(t, cfg)
	demux := deps.Demultiplexer
	requireStart(t, deps.Server)

	conn, err := net.Dial("udp", deps.Server.UDPLocalAddr())
	require.NoError(t, err, "cannot connect to DSD socket")
	defer conn.Close()

	// Test metric
	conn.Write([]byte("daemon:666|g|#foo:bar\ndaemon:666|g|#foo:bar"))
	samples, timedSamples := demux.WaitForSamples(time.Second * 2)
	assert.Equal(t, 2, len(samples))
	assert.Equal(t, 0, len(timedSamples))
	demux.Reset()
	demux.Stop(false)

	// EOL enabled
	cfg["dogstatsd_eol_required"] = []string{"udp"}

	deps = fulfillDepsWithConfigOverride(t, cfg)
	demux = deps.Demultiplexer
	requireStart(t, deps.Server)

	conn, err = net.Dial("udp", deps.Server.UDPLocalAddr())
	require.NoError(t, err, "cannot connect to DSD socket")
	defer conn.Close()

	// Test metric expecting an EOL
	_, err = conn.Write([]byte("daemon:666|g|#foo:bar\ndaemon:666|g|#foo:bar"))
	require.NoError(t, err, "cannot write to DSD socket")
	samples, timedSamples = demux.WaitForSamples(time.Second * 2)
	require.Equal(t, 1, len(samples))
	assert.Equal(t, 0, len(timedSamples))
	demux.Reset()
}
