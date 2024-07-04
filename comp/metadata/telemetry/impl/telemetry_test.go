// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package telemetryimpl

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/DataDog/datadog-agent/comp/core/telemetry"
	"github.com/DataDog/datadog-agent/comp/core/telemetry/telemetryimpl"
	"github.com/DataDog/datadog-agent/pkg/util/fxutil"
)

func TestNewComponent(t *testing.T) {
	telemetryComp := fxutil.Test[telemetry.Component](t, telemetryimpl.MockModule())

	tc := NewComponent(Requires{telemetryComp})
	tc.Increment("host")
	tc.Increment("inventory")
	tc.Increment("host")

	telemetryMock := telemetryComp.(telemetry.Mock)
	metrics, err := telemetryMock.GetCountMetric("metadata_payload", "sent_total")
	require.NoError(t, err)

	require.Len(t, metrics, 2)

	idxHost := slices.IndexFunc(metrics, func(m telemetry.Metric) bool {
		return m.Tags()["payload_name"] == "host"
	})
	require.NotEqual(t, -1, idxHost)
	require.EqualValues(t, 2, metrics[idxHost].Value())

	idxInventory := slices.IndexFunc(metrics, func(m telemetry.Metric) bool {
		return m.Tags()["payload_name"] == "inventory"
	})
	require.NotEqual(t, -1, idxInventory)
	require.EqualValues(t, 1, metrics[idxInventory].Value())
}
