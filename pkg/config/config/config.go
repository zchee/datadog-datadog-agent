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

	c := newConfig(opts)

	c.loadDefaults(opts)
	c.loadEnvVars(opts)
	warnings, err := c.loadYaml(opts)

	// All data are loaded, we now merge them into a single map
	c.generate()

	// we copy the knownKeys list so editing Option won't impact the config
	for k := range opts.knownKeys {
		// for each key we register every part of the key as known.
		//
		// for example, with a "a.b.c" key, "a", "a.b" and "a.b.c" will be known

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

// loadDefaults loads all the default for all known keys
func (c *config) loadDefaults(opts *Option) {
	for key, value := range opts.defaults {
		c.defaultData[key] = value
	}
}

func (c *config) applyTransformer(key string, envName string, opts *Option) {
	value, found := os.LookupEnv(envName)
	if !found {
		return
	}

	if fn, found := opts.envKeyTransformer[key]; found {
		c.envVarData[key] = fn(value)
	} else {
		c.envVarData[key] = value
	}
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

// loadYaml loads all the yaml files looking for known key inside.
func (c *config) loadYaml(opts *Option) ([]string, error) {
	warnings := []string{}

	for _, file := range opts.yamlFiles {
		config := map[string]interface{}{}
		content, err := os.ReadFile(file)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("error reading configuration file '%s': %s", file, err))
		}

		// Try UnmarshalStrict first, so we can warn about duplicated keys
		if strictErr := yaml.UnmarshalStrict(content, &config); strictErr != nil {
			config = map[string]interface{}{}
			warnings = append(warnings, fmt.Sprintf("warning reading config file: %v\n", strictErr))
			if err := yaml.Unmarshal(content, &config); err != nil {
				return warnings, err
			}
		}

		// For search each known key in the loaded data
		for key := range opts.knownKeys {
			keyParts := strings.Split(key, opts.keyDelim)
			value, err := getAndDeletePathFromMap(keyParts, config)
			if err == nil {
				c.fileData[key] = value
			}
		}
		if len(config) != 0 {
			// warn about unknown key
		}
	}

	return warnings, nil
}

// setLowerCase sets a path into the current configuration, creating node as needed.
// 'key' is a lowercase string like using keyDelim to separate config name (ie: 'logs_config.enabled').
func (c *config) setLowerCase(conf map[string]interface{}, key string, value interface{}) error {
	keyParts := strings.Split(key, c.keyDelim)

	for i := 0; i < len(keyParts)-1; i++ {
		currentPart := keyParts[i]

		if entry, exists := conf[currentPart]; !exists {
			newEntry := map[string]interface{}{}
			conf[currentPart] = newEntry
			conf = newEntry
		} else {
			if newConf, ok := entry.(map[string]interface{}); ok {
				conf = newConf
				continue
			}
			// this should never happen since we're working on known key that don't overlap
			return fmt.Errorf("unexpected error")
		}
	}
	conf[keyParts[len(keyParts)-1]] = value
	return nil
}

// generate takes all the loaded sources for settings and merge them together.
// All sources are merged in order of least important: default < file < env vars.
//
// The sources are map of key:value like:
//
//	"logs_config.enabled": true
//	"logs_config.proxy": {"http_proxy": "URL", "https_proxy": "URL"}
//
// The result is a map of settings like:
//
//	logs_config:
//		enabled: true
//		proxy:
//			http_proxy: URL
//			https_proxy: URL
func (c *config) generate() {
	// Default first
	for key, value := range c.defaultData {
		c.setLowerCase(c.data, key, value)
	}

	// Files next
	for key, value := range c.fileData {
		c.setLowerCase(c.data, key, value)
	}

	// Env vars
	for key, value := range c.envVarData {
		c.setLowerCase(c.data, key, value)
	}
}

//
// helpers
//

// getAndDeletePathFromMap return a value the data map at the give path and deletes it. The deletion prune known settings from
// the configuration allowing us to warning about unknown settings.
func getAndDeletePathFromMap(path []string, data map[string]interface{}) (interface{}, error) {
	if len(path) == 0 {
		return nil, fmt.Errorf("invalid path")
	}

	entryName := path[0]
	if value, found := data[entryName]; found {
		// if we're at the last element we found our value
		if len(path) == 1 {
			delete(data, entryName)
			return value, nil
		}

		if mapValue, ok := value.(map[string]interface{}); ok {
			res, err := getAndDeletePathFromMap(path[1:], mapValue)
			if len(mapValue) == 0 {
				delete(data, entryName)
			}
			return res, err
		}
		return nil, fmt.Errorf("invalid path or value")
	}
	return nil, fmt.Errorf("unknown path")
}

// getPathFromMap return a value the data map at the give path and deletes it.
// TODO: fix duplication logic between getAndDeletePathFromMap and getPathFromMap
func getPathFromMap(path []string, data map[string]interface{}) (interface{}, error) {
	if len(path) == 0 {
		return nil, fmt.Errorf("invalid path")
	}

	entryName := path[0]
	if value, found := data[entryName]; found {
		// if we're at the last element we found our value
		if len(path) == 1 {
			return value, nil
		}

		if mapValue, ok := value.(map[string]interface{}); ok {
			res, err := getAndDeletePathFromMap(path[1:], mapValue)
			return res, err
		}
		return nil, fmt.Errorf("invalid path or value")
	}
	return nil, fmt.Errorf("unknown path")
}
