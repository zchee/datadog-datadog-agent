// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build darwin

package traceroute

import (
	"context"

	"github.com/DataDog/datadog-agent/pkg/networkpath/payload"
)

// MockTraceroute defines a structure for
// running traceroute from an agent running
// on macOS
type MockTraceroute struct {
	MockPath payload.NetworkPath
}

// NewMockTraceroute creates a new instance of MockTraceroute
func NewMockTraceroute() (Traceroute, error) {

	return &MockTraceroute{}, nil
}

// Run executes a traceroute
func (m *MockTraceroute) Run(_ context.Context, _ Config) (payload.NetworkPath, error) {
	return payload.NetworkPath{}, nil
}
