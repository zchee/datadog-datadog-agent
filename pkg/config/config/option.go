// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package config

import (
	"strings"
	"sync"
)

const (
	defaultKeyDelim = "."
)

// Option contains all the information needed to create a Config
type Option struct {
	// List of YAML files to load configuration from. Configurations will be loaded in order, each overriding
	// previously loaded data.
	yamlFiles []string
	// envPrefix is the prefis used to load env vars. This prefix is added to all keys when searching the
	// environment.
	// If envPrefix is empty, environment detection is disabled.
	envPrefix string
	// keyDelim is a string that used to split path in the configuration. By defaults it's ".".
	keyDelim string

	defaults  map[string]interface{}
	knownKeys map[string]struct{}

	envAliases        map[string]string
	envKeyTransformer map[string]EnvTransformer
	m                 sync.Mutex
}

// NewOption returns a new Option
func NewOption() *Option {
	return &Option{
		yamlFiles:         []string{},
		keyDelim:          defaultKeyDelim,
		defaults:          make(map[string]interface{}),
		knownKeys:         make(map[string]struct{}),
		envAliases:        make(map[string]string),
		envKeyTransformer: make(map[string]EnvTransformer),
	}
}

// AppendYamlFile append a YAML file to the list of file to be loaded. Yaml files will be loaded in append order.
func (o *Option) AppendYamlFile(filespath ...string) {
	o.m.Lock()
	defer o.m.Unlock()

	o.yamlFiles = append(o.yamlFiles, filespath...)
}

// SetKeyDelim set the delimiter for keys (default is a '.').
func (o *Option) SetKeyDelim(delimiter string) {
	o.m.Lock()
	defer o.m.Unlock()

	o.keyDelim = delimiter
}

// SetEnvPrefix set the environment prefix used to Lookup env vars.
func (o *Option) SetEnvPrefix(prefix string) {
	o.m.Lock()
	defer o.m.Unlock()

	o.envPrefix = prefix
}

// SetDefault regirster a defaults for a key and register that key as known.
func (o *Option) SetDefault(key string, val interface{}) {
	o.m.Lock()
	defer o.m.Unlock()

	key = strings.ToLower(key)
	o.defaults[key] = val
	o.setKnownLowercase(key)
}

func (o *Option) setKnownLowercase(key string) {
	o.knownKeys[key] = struct{}{}
}

// SetKnown registers a key as know. A key must be known to be loaded from configuration, env vars, ...
func (o *Option) SetKnown(key string) {
	o.m.Lock()
	defer o.m.Unlock()

	o.setKnownLowercase(strings.ToLower(key))
}

// AddEnvAlias registers an env vars alias for a settings. The key will be marked as known.
//
// Environment aliases are loaded after loading the environment for regular key.
//
// For example with an environment with 'DD_MY_KEY=1234' and 'DD_MY_ALIAS_KEY=5678':
//
//	c.EnvAlias("my_key", "MY_ALIAS_KEY")
//
//	// Get will return the value from the alias (ie. "5678")
//	c.Get("my_key)
func (o *Option) AddEnvAlias(key string, env string) {
	o.m.Lock()
	defer o.m.Unlock()

	key = strings.ToLower(key)
	o.envAliases[o.envPrefix+env] = key
	o.setKnownLowercase(key)
}

// SetEnvKeyTransformer regirster a function to be called to load env vars. The function will be called with the string
// value from the env var and its return will be used as values for that key.
//
// This also set 'key' as known.
func (o *Option) SetEnvKeyTransformer(key string, fn EnvTransformer) {
	o.m.Lock()
	defer o.m.Unlock()

	key = strings.ToLower(key)
	o.envKeyTransformer[key] = fn
	o.setKnownLowercase(key)
}
