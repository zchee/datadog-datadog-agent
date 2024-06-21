// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package config

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"
)

func TestGetStringsKeys(t *testing.T) {
	input := []byte(`
a: 1
b:
  c: "test"
  d: [1,2,3]
  e:
    f: 21
  g:
    h: "test"
    11: 23
`)
	data := map[interface{}]interface{}{}
	err := yaml.Unmarshal(input, &data)
	require.NoError(t, err)

	keys := getStringsKeys(data, "", ".")
	sort.Strings(keys)
	assert.Equal(t, []string{"a", "b.c", "b.d", "b.e.f", "b.g"}, keys)
}

//func TestMapToLowercase(t *testing.T) {
//	input := []byte(`
//a: 1
//B:
//  c: "test"
//  D: [1,"A",3]
//  e:
//   G: 21
//  11: "TEST"
//`)
//	data := map[interface{}]interface{}{}
//	err := yaml.Unmarshal(input, &data)
//	require.NoError(t, err)
//
//	mapToLowerCase(data)
//
//	expected := map[interface{}]interface{}{
//		"a": 1, // value overwritten by extra.yaml
//		"b": map[interface{}]interface{}{
//			"c": "test",
//			"d": []interface{}{1, "A", 3}, // types from loaded YAML are not typed
//			"e": map[interface{}]interface{}{"g": 21},
//			11:  "TEST",
//		},
//	}
//	assert.Equal(t, expected, data)
//}

func TestGetAndDeletePathFromMap(t *testing.T) {
	data := map[interface{}]interface{}{
		"a": map[interface{}]interface{}{
			"b": 1,
		},
		"b": "test",
	}

	_, err := getAndDeletePathFromMap([]string{"a", "b"}, data)
	assert.NoError(t, err)
	assert.Equal(t, map[interface{}]interface{}{"b": "test"}, data)
}

func TestGetAndDeletePathFromMapEmptyPath(t *testing.T) {
	data := map[interface{}]interface{}{
		"a": map[interface{}]interface{}{
			"b": 1,
		},
		"b": "test",
	}

	_, err := getAndDeletePathFromMap([]string{}, data)
	assert.Error(t, err)
}

func TestGetAndDeletePathFromMapInvalidKey(t *testing.T) {
	data := map[interface{}]interface{}{
		"a": map[interface{}]interface{}{
			"b": 1,
		},
		"b": "test",
	}

	_, err := getAndDeletePathFromMap([]string{"a", "b", "c"}, data)
	assert.Error(t, err)
}

func TestMergeMap(t *testing.T) {
	data1 := map[string]interface{}{
		"a": 1,
		"b": map[string]interface{}{
			"c": 2,
			"d": []int{1, 2, 3},
			"e": map[string]interface{}{
				"f": "test",
			},
		},
	}

	data2 := map[string]interface{}{
		"b": map[string]interface{}{
			"d": []int{4, 5},
			"e": map[string]interface{}{
				"g": "test2",
			},
		},
	}

	// copying data2 data into data1
	mergeMap(data2, data1)

	expected := map[string]interface{}{
		"a": 1,
		"b": map[string]interface{}{
			"c": 2,
			"d": []int{4, 5},
			"e": map[string]interface{}{
				"f": "test",
				"g": "test2",
			},
		},
	}

	assert.Equal(t, expected, data1)
}
