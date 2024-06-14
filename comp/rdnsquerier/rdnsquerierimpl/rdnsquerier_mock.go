// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

//go:build test

package rdnsquerierimpl

import (
	"go.uber.org/fx"

	"github.com/DataDog/datadog-agent/pkg/util/fxutil"
)

// MockModule defines the fx options for the mock component.
func MockModule() fxutil.Module {
	return fxutil.Component(
		fx.Provide(newMock),
	)
}

type rdnsQuerierMock struct{}

// JMWTESTSPASS
func (q *rdnsQuerierMock) GetHostname(_ []byte) string {
	return ""
}

/* JMWBREAKSTESTS need to figure out how to regenerate the pcap files
func (q *rdnsQuerierMock) GetHostname(ipAddr []byte) string {
	ip := net.IP(ipAddr)
	if !ip.IsPrivate() { // JMW IsPrivate() also returns false for invalid IP addresses JMWCHECK
		return "hostname-" + ip.String()
	}
	return ""
}
*/

func newMock() provides {
	// Mock initialization
	return provides{
		Comp: &rdnsQuerierMock{},
	}
}
