// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v2"
)

func newConfig(opts *Option) *config {
	return &config{
		data:        make(map[string]interface{}),
		keyDelim:    opts.keyDelim,
		knownKeys:   make(map[string]struct{}),
		defaultData: make(map[string]interface{}),
		envVarData:  make(map[string]interface{}),
		fileData:    make(map[string]interface{}),
		runtimeData: make(map[string]interface{}),
	}
}

// Load returns a fully initialized Config based on the given Option.
func Load(opts *Option) (Config, []string, error) {
	opts.m.Lock()
	defer opts.m.Unlock()

	if err := opts.validateKeys(); err != nil {
		return nil, nil, err
	}

	c := newConfig(opts)

	c.loadDefaults(opts)
	c.loadEnvVars(opts)
	warnings, err := c.loadYaml(opts)
	if err != nil {
		return nil, warnings, err
	}

	// All data are loaded succesfully, we now merge them into a single map
	c.generate()

	// we copy the knownKeys list so editing Option won't impact the config
	for k := range opts.knownKeys {
		// for each key we register every part of the key as known.

		curKey := ""
		for _, part := range strings.Split(k, c.keyDelim) {
			if curKey == "" {
				curKey = part
			} else {
				curKey += c.keyDelim + part
			}
			c.knownKeys[curKey] = struct{}{}
		}
	}

	return c, warnings, err
}

// loadDefaults loads all the default values
func (c *config) loadDefaults(opts *Option) {
	for key, value := range opts.defaults {
		setInMap(key, opts.keyDelim, c.defaultData, value)
	}
}

func (c *config) applyTransformer(key string, envName string, opts *Option) {
	envVal, found := os.LookupEnv(envName)
	if !found {
		return
	}

	var value interface{}
	if fn, found := opts.envKeyTransformer[key]; found {
		value = fn(envVal)
	} else {
		value = envVal
	}

	setInMap(key, opts.keyDelim, c.envVarData, value)
}

// loadEnvVars looks up all known keys from the env vars and loading them.
func (c *config) loadEnvVars(opts *Option) {
	if opts.envPrefix == "" {
		return
	}

	// We loop over all known keys in the environment
	for key := range opts.knownKeys {
		envName := opts.envPrefix + strings.Replace(strings.ToUpper(key), ".", "_", -1)
		c.applyTransformer(key, envName, opts)
	}

	// We then load all the aliases
	for envName, key := range opts.envAliases {
		c.applyTransformer(key, envName, opts)
	}
}

// loadYaml loads all the yaml files looking for known keys inside.
//
// We load the data from all files in sequential order looking for known keys inside. Any keys left after this will
// create warnings about unknown keys.
func (c *config) loadYaml(opts *Option) ([]string, error) {
	warnings := []string{}

	for _, file := range opts.yamlFiles {
		content, err := os.ReadFile(file)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("error reading configuration file '%s': %s", file, err))
			continue
		}

		// Try UnmarshalStrict first, so we can warn about duplicated keys.
		//
		// The yaml lib will load any map as map[interface{}]interface{}. We use this type for loading but will
		// enforce map[string]interface{} when ingesting the data in c.fileData (through setInMap)
		conf := map[interface{}]interface{}{}
		if strictErr := yaml.UnmarshalStrict(content, &conf); strictErr != nil {
			warnings = append(warnings, fmt.Sprintf("warning reading config file '%s': %v\n", file, strictErr))

			// reset the config
			conf = map[interface{}]interface{}{}
			if err := yaml.Unmarshal(content, &conf); err != nil {
				return warnings, err
			}
		}

		// Convert the loaded YAML to lowercase. Since we're looking to known keys into the loaded YAML we need
		// it to be lowercase.
		mapToLowerCase(conf)

		// For search each known key in the loaded data
		for key := range opts.knownKeys {
			keyParts := strings.Split(key, opts.keyDelim)
			value, err := getAndDeletePathFromMap(keyParts, conf)
			if err == nil {
				// setInMap will lowercase the key
				setInMap(key, opts.keyDelim, c.fileData, value)
			}
		}
		// If any data is left in the config from the YAML file we warn about them being unknown.
		if len(conf) != 0 {
			for _, unknownKey := range getStringsKeys(conf, "", opts.keyDelim) {
				warnings = append(warnings,
					fmt.Sprintf("unknown configuration setting '%s'", unknownKey),
				)
			}
		}
	}

	return warnings, nil
}

// generate takes all the loaded sources for settings and merge them together.
// All sources are merged in order of least important: default < file < env vars.
func (c *config) generate() {
	// Default first
	mergeMap(c.defaultData, c.data)

	// Files next
	mergeMap(c.fileData, c.data)

	// Env vars
	mergeMap(c.envVarData, c.data)
}
