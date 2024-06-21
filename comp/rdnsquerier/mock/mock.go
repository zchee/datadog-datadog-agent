// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

//go:build test

// Package mock provides the rdnsquerier mock component
package mock

import (
	"net/netip"

	rdnsquerier "github.com/DataDog/datadog-agent/comp/rdnsquerier/def"
)

// Mock implements mock-specific methods.
type Mock interface {
	rdnsquerier.Component
}

type rdnsQuerierMock struct{}

// NewMock returns a mock for the rdnsquerier component.
func NewMock() rdnsquerier.Component {
	return &rdnsQuerierMock{}
}

func (m *rdnsQuerierMock) GetHostnameEmptyString(_ []byte) string {
	return ""
}

// JMWBREAKSTESTS need to figure out how to regenerate the pcap files
func (q *rdnsQuerierMock) GetHostname(ipAddr []byte) string {
	ipaddr, ok := netip.AddrFromSlice(ipAddr)
	if !ok {
		return ""
	}

	if !ipaddr.IsPrivate() {
		return ""
	}

	// JMW make sure the tests have some private IPs to test - and/or add some
	return "hostname-" + ipaddr.String()
}
