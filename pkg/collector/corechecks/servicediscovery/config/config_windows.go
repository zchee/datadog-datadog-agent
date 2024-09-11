// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package config holds config related files
package config

import (
	coreconfig "github.com/DataDog/datadog-agent/pkg/config"
)

const (
	// DefaultEventBurst is the default value for event burst with the process
	// data event stream.
	DefaultEventBurst = 40
)

// Config defines the config
type Config struct {
	// EventServerBurst defines the maximum burst of events that can be sent over the grpc server
	EventBurst int
}

// NewConfig creates a config for the service discovery for Windows
func NewConfig() *Config {
	config := &Config{
		EventBurst: coreconfig.SystemProbe().GetInt("discovery.event_burst"),
	}

	if config.EventBurst == 0 {
		config.EventBurst = DefaultEventBurst
	}

	return config
}
