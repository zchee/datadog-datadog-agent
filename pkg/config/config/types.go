// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package config

import (
	"sync"
)

// EnvTransformer convert strings from the environment into other types
type EnvTransformer func(string) interface{}

type config struct {
	// data is the current configuration fully loaded as a tree
	data map[string]interface{}
	// keyDelim is a string that used to split path in the configuration. By defaults it's ".".
	keyDelim string

	// knownKeys list all the known keys in the configuration, include intermediate path.
	// Not all known key are set. A key can be set as known without a default value.
	//
	// ex: for a 'a.b.c' key, all 'a', 'a.b' and 'a.b.c' will be known
	knownKeys map[string]struct{}

	// Those layers contain all known keys for each source.
	// The format use the full known key as the map entry:
	//
	// ex:
	//	"remote_configuration.apm_sampling.enabled": <value>
	//	"remote_configuration.agent_integrations.enabled": <value>
	//	"remote_configuration.agent_integrations.allow_log_config_scheduling": <value>
	//	...
	defaultData map[string]interface{}
	fileData    map[string]interface{}
	envVarData  map[string]interface{}
	runtimeData map[string]interface{}

	unknownKeyWarnings map[string]string

	m sync.RWMutex
}

// Config is an interface to access a configuration
type Config interface {
	Get(string) interface{}
	// Set(string, interface{})
}
