// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package config

import (
	"fmt"
	"strings"
)

// getStringsKeys returns a list of all keys from a map. This is meant to get all keys from a loaded YAML.
//
// This recursively travers the map looking for strings key in map trying to create the longest key.
// Example the following YAML will generate 3 key 'a', 'b.c', 'b.d', "e" (with keyDelim is '.'):
//
//	a: 21
//	b:
//	  c: "data"
//	  d: [1, 2, 3]
//	e:
//	  f: "test"
//	  11: 12
func getStringsKeys(data map[interface{}]interface{}, prefix string, keyDelim string) []string {
	warnings := []string{}

	keys := []string{}
	for k := range data {
		if kString, ok := k.(string); ok {
			keys = append(keys, kString)
		} else {
			// the map contains 1 non string element meaning that other entry can't be strings
			return []string{prefix}
		}
	}

	for _, kString := range keys {
		var newPrefix string
		if prefix != "" {
			newPrefix = prefix + keyDelim + kString
		} else {
			newPrefix = kString
		}

		if vMap, ok := data[kString].(map[interface{}]interface{}); ok {
			warnings = append(warnings, getStringsKeys(vMap, newPrefix, keyDelim)...)
		} else {
			warnings = append(warnings, newPrefix)
		}
	}
	return warnings
}

func setInMap(key string, keyDelim string, data map[string]interface{}, value interface{}) {
	keyParts := strings.Split(strings.ToLower(key), keyDelim)

	// At this point opts has been validated, we know that no keys overlap.
	for _, part := range keyParts[:len(keyParts)-1] {
		if value, found := data[part]; found {
			data = value.(map[string]interface{})
		} else {
			data[part] = map[string]interface{}{}
			data = data[part].(map[string]interface{})
		}
	}
	data[keyParts[len(keyParts)-1]] = value
}

// mapToLowerCase iterate throught a map converting all strings key to lowercase
func mapToLowerCase(data map[interface{}]interface{}) {
	for k, v := range data {
		if kString, ok := k.(string); ok {
			kLower := strings.ToLower(kString)
			if kString != kLower {
				data[strings.ToLower(kString)] = v
				delete(data, kString)
			}
		}
		if kMap, ok := v.(map[interface{}]interface{}); ok {
			mapToLowerCase(kMap)
		}
	}
}

// getAndDeletePathFromMap return a value from the data map at the give path and deletes it. The deletion prune known
// settings from the configuration allowing us to warning about unknown settings in the end.
func getAndDeletePathFromMap(path []string, data map[interface{}]interface{}) (interface{}, error) {
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

		if mapValue, ok := value.(map[interface{}]interface{}); ok {
			res, err := getAndDeletePathFromMap(path[1:], mapValue)
			if len(mapValue) == 0 {
				delete(data, entryName)
			}
			return res, err
		}
		return nil, fmt.Errorf("invalid path or value")
	}
	return nil, fmt.Errorf("key not found in data")
}

func mergeMap(src map[string]interface{}, dest map[string]interface{}) {
	for k, v := range src {
		if vMap, ok := v.(map[string]interface{}); ok {
			if _, ok := dest[k]; !ok {
				dest[k] = map[string]interface{}{}
			}
			mergeMap(vMap, dest[k].(map[string]interface{}))
		} else {
			dest[k] = v
		}
	}
}

// getPathFromMap return a value the data map at the give path and deletes it.
func getPathFromMap(path []string, data map[string]interface{}) (interface{}, error) {
	return nil, nil
}
