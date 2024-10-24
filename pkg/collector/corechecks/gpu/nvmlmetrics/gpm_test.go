// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

//go:build linux

package nvmlmetrics

import (
	"testing"

	"github.com/NVIDIA/go-nvml/pkg/nvml"
	nvmlmock "github.com/NVIDIA/go-nvml/pkg/nvml/mock"
	"github.com/stretchr/testify/require"
)

func TestGpmCollectorChecksUnsupportedDevice(t *testing.T) {
	dev := &nvmlmock.Device{
		GpmQueryDeviceSupportFunc: func() (nvml.GpmSupport, nvml.Return) {
			return nvml.GpmSupport{IsSupportedDevice: 0}, nvml.SUCCESS
		},
	}

	collector, err := newGpmMetricsCollector(&nvmlmock.Interface{}, dev, nil)
	require.Nil(t, collector)
	require.ErrorIs(t, err, errUnsupportedDevice)
}

type mockGpmSampleWithId struct {
	nvmlmock.GpmSample
	id int
}

func requireSampleId(t *testing.T, sample nvml.GpmSample, expectedId int) {
	t.Helper()
	mockSample, ok := sample.(*mockGpmSampleWithId)
	require.True(t, ok)
	require.Equal(t, expectedId, mockSample.id)
}

func TestGpmCollectorAdvancesSamplesCorrectly(t *testing.T) {
	sample1 := &mockGpmSampleWithId{id: 1}
	sample2 := &mockGpmSampleWithId{id: 2}

	collector := &gpmMetricsCollector{
		currentSampleIndex: 0,
		samples:            [numGpmSamples]nvml.GpmSample{sample1, sample2},
	}

	requireSampleId(t, collector.currentSample(), 1)
	requireSampleId(t, collector.previousSample(), 2)

	collector.markCollectedSample()
	requireSampleId(t, collector.currentSample(), 2)
	requireSampleId(t, collector.previousSample(), 1)
}

func TestGpmCollectorRetrievesMetricsCorrectly(t *testing.T) {
	gpmSampleGetFunc := func(_ nvml.Device) nvml.Return {
		return nvml.SUCCESS
	}

	gpmSamples := [numGpmSamples]*mockGpmSampleWithId{
		{id: 1, GpmSample: nvmlmock.GpmSample{GetFunc: gpmSampleGetFunc}},
		{id: 2, GpmSample: nvmlmock.GpmSample{GetFunc: gpmSampleGetFunc}},
	}
	returnedSampleId := 0
	lib := &nvmlmock.Interface{
		GpmSampleAllocFunc: func() (nvml.GpmSample, nvml.Return) {
			smpl := gpmSamples[returnedSampleId]
			returnedSampleId++
			return smpl, nvml.SUCCESS
		},
		GpmMetricsGetFunc: func(metricsGet *nvml.GpmMetricsGetType) nvml.Return {
			return nvml.SUCCESS
		},
	}
	dev := &nvmlmock.Device{
		GpmQueryDeviceSupportFunc: func() (nvml.GpmSupport, nvml.Return) {
			return nvml.GpmSupport{IsSupportedDevice: 1}, nvml.SUCCESS
		},
	}

	collector, err := newGpmMetricsCollector(lib, dev, nil)
	require.NoError(t, err)
	require.NotNil(t, collector)

	gpmCollector, ok := collector.(*gpmMetricsCollector)
	require.True(t, ok)

	// Ensure we have allocated two samples
	require.Len(t, lib.GpmSampleAllocCalls(), numGpmSamples)

	// Check that we have the correct samples
	requireSampleId(t, gpmCollector.currentSample(), 1)
	requireSampleId(t, gpmCollector.previousSample(), 2)

	// First collect call, we shouldn't get metrics
	metrics, err := collector.Collect()
	require.NoError(t, err)
	require.Empty(t, metrics)
	require.Len(t, lib.GpmMetricsGetCalls(), 0)
	require.Len(t, gpmSamples[0].GetCalls(), 1)
	require.Len(t, gpmSamples[1].GetCalls(), 0)
	requireSampleId(t, gpmCollector.currentSample(), 2)
	requireSampleId(t, gpmCollector.previousSample(), 1)

	// Second collect call, we should get metrics
	metrics, err = collector.Collect()
	require.NoError(t, err)
	require.NotEmpty(t, metrics)
	require.Len(t, lib.GpmMetricsGetCalls(), 1)
	require.Len(t, gpmSamples[0].GetCalls(), 1)
	require.Len(t, gpmSamples[1].GetCalls(), 1)
	requireSampleId(t, gpmCollector.currentSample(), 1)
	requireSampleId(t, gpmCollector.previousSample(), 2)
}
