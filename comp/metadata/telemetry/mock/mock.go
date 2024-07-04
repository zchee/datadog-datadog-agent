// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

//go:build test

// Package mock implements a mock for the metadata telemetry component.
package mock

import (
	"testing"

	"github.com/stretchr/testify/mock"

	telemetry "github.com/DataDog/datadog-agent/comp/metadata/telemetry/def"
)

var _ telemetry.Component = (*TelemetryMock)(nil)

// Mock returns a mock for metadata telemetry component.
func Mock(t *testing.T) *TelemetryMock {
	tm := &TelemetryMock{}
	tm.Test(t)

	t.Cleanup(func() {
		tm.AssertExpectations(t)
	})

	return &TelemetryMock{}
}

// TelemetryMock is the mock type.
type TelemetryMock struct {
	mock.Mock
}

// Increment increments the counter for the given payload name.
func (m *TelemetryMock) Increment(payloadName string) {
	m.Called(payloadName)
}
