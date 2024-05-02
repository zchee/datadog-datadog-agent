// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package config

import "strings"

// EnvTransformer convert strings from the environment into other types
type EnvTransformer func(string) interface{}

type Option struct {
	YamlFiles []string
	EnvPrefix string

	defaults  map[string]interface{}
	knownKeys map[string]struct{}

	envBinding        map[string]string
	envKeyTransformer map[string]EnvTransformer
}

func (o *Option) SetDefault(key string, val interface{}) {
	key = strings.ToLower(key)
	o.defaults[key] = val
	o.knownKeys[key] = struct{}{}
}

func (o *Option) SetKnown(key string) {
	o.knownKeys[strings.ToLower(key)] = struct{}{}
}

func (o *Option) BindEnv(key string, env string) {
	key = strings.ToLower(key)
	o.envBinding[env] = key
	o.knownKeys = struct{}{}
}

func (o *Option) SetEnvKeyTransformer(key string, fn EnvTransformer) {
	key = strings.ToLower(key)
	o.envKeyTransformer[key] = fn
	o.knownKeys[key] = struct{}{}
}

type Config struct {
	settings map[string]interface{}
	data     map[string]interface{}

	defaultData map[string]interface{}
	fileData    map[string]interface{}
	envVarsData map[string]interface{}
	runtimeData map[string]interface{}
}
