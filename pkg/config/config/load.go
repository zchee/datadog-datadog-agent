// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package config

import (
	"os"
	"strings"
)

// Load returns a fully initialized Config
func Load(opts Option) Config {
}

func (c *Config) loadEnvVars(opts Option) {
	if opts.EnvPrefix == "" {
		return
	}

	// We loop over all known keys in the environ for overwrite
	for _, key := range c.knownKeys {
		envName := o.EnvPrefix + strings.Replace(".", "_", strings.ToUpper(key))

		value, found := os.LookupEnv(envName)
		if !found {
			continue
		}

		if fn, found := o.envKeyTransformer(key); found {
			c.envVarsData[key] = fn(value)
		} else {
			c.envVarsData[key] = value
		}
	}
}
