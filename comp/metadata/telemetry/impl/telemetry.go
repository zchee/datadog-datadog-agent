// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

// Package telemetryimpl implements the telemetry component interface
package telemetryimpl

import (
	telemetryComp "github.com/DataDog/datadog-agent/comp/core/telemetry"
	telemetry "github.com/DataDog/datadog-agent/comp/metadata/telemetry/def"
)

// Requires defines the dependencies for the telemetry component
type Requires struct {
	telemetry telemetryComp.Component
}

// NewComponent creates a new metadata telemetry component
func NewComponent(reqs Requires) telemetry.Component {
	counter := reqs.telemetry.NewCounter("metadata_payload", "sent_total", []string{"payload_name"}, "Total number of metadata payloads sent")
	return &metadataCounter{
		counter,
	}
}

type metadataCounter struct {
	telemetryComp.Counter
}

func (mc *metadataCounter) Increment(payloadName string) {
	mc.Inc(payloadName)
}
