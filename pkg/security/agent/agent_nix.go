// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux

package agent

import (
	"errors"

	"go.uber.org/atomic"

	workloadmeta "github.com/DataDog/datadog-agent/comp/core/workloadmeta/def"
	"github.com/DataDog/datadog-agent/pkg/security/security_profile/dump"
	"github.com/DataDog/datadog-go/v5/statsd"
)

// NewRuntimeSecurityAgent instantiates a new RuntimeSecurityAgent
func NewRuntimeSecurityAgent(statsdClient statsd.ClientInterface, hostname string, opts RSAOptions, wmeta workloadmeta.Component) (*RuntimeSecurityAgent, error) {
	client, err := NewRuntimeSecurityClient()
	if err != nil {
		return nil, err
	}

	// on windows do no telemetry
	telemetry, err := newTelemetry(statsdClient, wmeta)
	if err != nil {
		return nil, errors.New("failed to initialize the telemetry reporter")
	}

	profContainersTelemetry, err := newProfContainersTelemetry(statsdClient, wmeta, opts.LogProfiledWorkloads)
	if err != nil {
		return nil, errors.New("failed to initialize the profiled containers telemetry reporter")
	}

	// on windows do no storage manager
	storage, err := dump.NewAgentStorageManager()
	if err != nil {
		return nil, err
	}

	return &RuntimeSecurityAgent{
		client:                  client,
		hostname:                hostname,
		telemetry:               telemetry,
		profContainersTelemetry: profContainersTelemetry,
		storage:                 storage,
		running:                 atomic.NewBool(false),
		connected:               atomic.NewBool(false),
		eventReceived:           atomic.NewUint64(0),
		activityDumpReceived:    atomic.NewUint64(0),
	}, nil
}
