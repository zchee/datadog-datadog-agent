// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux && !arm64

// Package modules is all the module definitions for system-probe
package modules

import (
	"time"

	"github.com/DataDog/datadog-agent/cmd/system-probe/api/module"
)

// All System Probe modules should register their factories here
var All = []module.Factory{
	EBPFProbe,
	NetworkTracer,
	TCPQueueLength,
	OOMKillProbe,
	Process,
	DynamicInstrumentation,
	LanguageDetectionModule,
	ComplianceModule,
	Pinger,
	Traceroute,
	DiscoveryModule,
	GPUMonitoring,
	// Other modules (NetworkTracer,GpuMonitoring,DynamicInstrumentation) use the process
	// monitor so they must set up their callbacks before we call initializes
	ProcessMonitor,
	// EventMonitor must be initialized after ProcessMonitor, if we are using EventStream
	// for process monitoring, starting the event monitor will scan existing processes
	EventMonitor,
}

func inactivityEventLog(_ time.Duration) {

}
