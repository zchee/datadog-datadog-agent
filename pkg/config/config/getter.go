// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package config

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cast"
	"github.com/spf13/viper"
)

// Get returns a key from the configuration
func (c *config) Get(key string) interface{} {
	c.m.RLock()
	defer c.m.RUnlock()

	key = strings.ToLower(key)
	value, _ := getPathFromMap(strings.Split(key, c.keyDelim), c.data)
	return value
}

// GetString returns a key from the configuration cast as a string
func (c *config) GetString(key string) string {
	return cast.ToString(c.Get(key))
}

// GetBool returns a key from the configuration cast as a bool
func (c *config) GetBool(key string) bool {
	return cast.ToBool(c.Get(key))
}

// GetInt returns a key from the configuration cast as a int
func (c *config) GetInt(key string) int {
	return cast.ToInt(c.Get(key))
}

// GetInt32 returns a key from the configuration cast as a int32
func (c *config) GetInt32(key string) int32 {
	return cast.ToInt32(c.Get(key))
}

// GetInt64 returns a key from the configuration cast as a int64
func (c *config) GetInt64(key string) int64 {
	return cast.ToInt64(c.Get(key))
}

// GetFloat64 returns a key from the configuration cast as a float64
func (c *config) GetFloat64(key string) float64 {
	return cast.ToFloat64(c.Get(key))
}

// GetTime returns a key from the configuration cast as a time.Time
func (c *config) GetTime(key string) time.Time {
	return cast.ToTime(c.Get(key))
}

// GetDuration returns a key from the configuration cast as a time.Duration
func (c *config) GetDuration(key string) time.Duration {
	return cast.ToDuration(c.Get(key))
}

// GetStringSlice returns a key from the configuration cast as a []string
func (c *config) GetStringSlice(key string) []string {
	return cast.ToStringSlice(c.Get(key))
}

// GetFloat64SliceE returns a key from the configuration cast as a []float64
func (c *config) GetFloat64SliceE(key string) ([]float64, error) {
	list, err := cast.ToSliceE(c.Get(key))
	if err != nil {
		return nil, fmt.Errorf("'%v' is not a list", key)
	}

	res := []float64{}
	for _, item := range list {
		nb, err := cast.ToFloat64E(item)
		if err != nil {
			return nil, fmt.Errorf("value '%v' from '%v' is not a float64", item, key)
		}
		res = append(res, nb)
	}
	return res, nil
}

// GetStringMap returns a key from the configuration cast as a map[string]interface{}
func (c *config) GetStringMap(key string) map[string]interface{} {
	return cast.ToStringMap(c.Get(key))
}

// GetStringMapString returns a key from the configuration cast as a map[string]string
func (c *config) GetStringMapString(key string) map[string]string {
	return cast.ToStringMapString(c.Get(key))
}

// GetStringMapStringSlice returns a key from the configuration cast as a map[string][]string
func (c *config) GetStringMapStringSlice(key string) map[string][]string {
	return cast.ToStringMapStringSlice(c.Get(key))
}

// AllSettings returns a copy of the current configuration
func (c *config) AllSettings() map[string]interface{} {
	c.m.RLock()
	defer c.m.RUnlock()

	// TODO: implement actual deepcopy
	configCopy := map[string]interface{}{}
	str, _ := json.Marshal(c.data)
	_ = json.Unmarshal(str, &configCopy)
	return configCopy
}

// AllSettingsWithoutDefault returns a copy of the current configuration without default
func (c *config) AllSettingsWithoutDefault() map[string]interface{} {
	c.m.RLock()
	defer c.m.RUnlock()

	settings := map[string]interface{}{}

	// Files next
	for key, value := range c.fileData {
		c.setLowerCase(settings, key, value)
	}

	// Env vars
	for key, value := range c.envVarData {
		c.setLowerCase(settings, key, value)
	}

	// Runtime
	for key, value := range c.runtimeData {
		c.setLowerCase(settings, key, value)
	}

	// TODO: implement actual deepcopy or directly return a YAML
	settingsCopy := map[string]interface{}{}
	str, _ := json.Marshal(settings)
	_ = json.Unmarshal(str, &settingsCopy)
	return settingsCopy
}

// AllKeysLowercased returns all known keys from the configuration
func (c *config) AllKeysLowercased() []string {
	c.m.RLock()
	defer c.m.RUnlock()

	knownKeys := make([]string, 0, len(c.knownKeys))
	for k := range c.knownKeys {
		knownKeys = append(knownKeys, k)
	}
	return knownKeys
}

// IsKnown returns true if a key is known. Some known key might not have value in the configuration
//
// See IsSet method to check if a key as a value.
func (c *config) IsKnown(key string) bool {
	c.m.RLock()
	defer c.m.RUnlock()

	_, found := c.knownKeys[strings.ToLower(key)]
	return found
}

// IsSet returns true if a key has a value in the configuration. Not all known key have value.
//
// See IsKnown to check if a key is known.
func (c *config) IsSet(key string) bool {
	c.m.RLock()
	defer c.m.RUnlock()

	key = strings.ToLower(key)
	if _, found := c.defaultData[key]; found {
		return true
	}
	if _, found := c.envVarData[key]; found {
		return true
	}
	if _, found := c.fileData[key]; found {
		return true
	}
	if _, found := c.runtimeData[key]; found {
		return true
	}
	return false
}

func (c *config) UnmarshalKey(key string, rawVal interface{}, opts ...viper.DecoderConfigOption) error {
	return nil
}
