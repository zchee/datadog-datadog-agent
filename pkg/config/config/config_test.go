// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package config

import (
	"encoding/json"
	"path"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewConfig(t *testing.T) {
	opts := NewOption()
	c := newConfig(opts)
	assert.Equal(t, defaultKeyDelim, c.keyDelim)

	opts.SetKeyDelim("-")
	c = newConfig(opts)
	assert.Equal(t, "-", c.keyDelim)
}

func TestLoadDefaults(t *testing.T) {
	opts := NewOption()
	opts.SetDefault("a", 21)
	opts.SetDefault("b.a", "test")
	opts.SetDefault("b.b", []int{1, 2, 3})

	conf, warnings, err := Load(opts)
	c := conf.(*config)
	assert.NoError(t, err)
	assert.Empty(t, warnings)

	expected := map[string]interface{}{
		"a": 21,
		"b": map[string]interface{}{
			"a": "test",
			"b": []int{1, 2, 3},
		},
	}
	assert.Equal(t, expected, c.defaultData)
}

func TestLoadEnvEmptyPrefix(t *testing.T) {
	// Not setting envPrefix should disabled any env lookup
	opts := NewOption()
	opts.SetKnown("a")

	t.Setenv("TEST_A", "test")

	conf, warnings, err := Load(opts)
	c := conf.(*config)
	assert.NoError(t, err)
	assert.Empty(t, warnings)

	assert.Empty(t, c.envVarData)
}

func TestLoadEnv(t *testing.T) {
	opts := NewOption()
	opts.SetKnown("a")
	opts.SetEnvPrefix("TEST_")

	t.Setenv("TEST_A", "test")

	conf, warnings, err := Load(opts)
	c := conf.(*config)
	assert.NoError(t, err)
	assert.Empty(t, warnings)

	assert.Equal(t, "test", c.envVarData["a"])
}

func TestLoadEnvWithTransformer(t *testing.T) {
	opts := NewOption()
	opts.SetKnown("a")
	opts.SetKnown("b.a")
	opts.SetKnown("b.c")
	opts.SetEnvPrefix("TEST_")
	opts.SetEnvKeyTransformer("b.c", func(data string) interface{} {
		res := []int{}
		err := json.Unmarshal([]byte(data), &res)
		require.NoError(t, err)
		return res
	})

	t.Setenv("TEST_A", "21")
	t.Setenv("TEST_B_A", "test")
	t.Setenv("TEST_B_C", "[1,2,3]")

	conf, warnings, err := Load(opts)
	c := conf.(*config)
	assert.NoError(t, err)
	assert.Empty(t, warnings)

	expected := map[string]interface{}{
		"a": "21", // no automatic cast to int
		"b": map[string]interface{}{
			"a": "test",
			"c": []int{1, 2, 3},
		},
	}
	assert.Equal(t, expected, c.envVarData)
}

func TestLoadEnvWithAliases(t *testing.T) {
	opts := NewOption()
	opts.SetKnown("a")
	opts.SetKnown("b.a")
	opts.SetKnown("b.c")
	opts.AddEnvAlias("b.a", "MY_ALIAS_KEY_A")
	opts.AddEnvAlias("b.c", "MY_ALIAS_KEY_C")
	opts.SetEnvPrefix("TEST_")

	opts.SetEnvKeyTransformer("b.c", func(data string) interface{} {
		res := []int{}
		err := json.Unmarshal([]byte(data), &res)
		require.NoError(t, err)
		return res
	})

	t.Setenv("TEST_A", "21")
	t.Setenv("MY_ALIAS_KEY_A", "test")
	t.Setenv("TEST_B_C", "[1,2,3]")
	t.Setenv("MY_ALIAS_KEY_C", "[4,5,6]")

	conf, warnings, err := Load(opts)
	c := conf.(*config)
	assert.NoError(t, err)
	assert.Empty(t, warnings)

	expected := map[string]interface{}{
		"a": "21", // no automatic cast to int
		"b": map[string]interface{}{
			"a": "test",
			"c": []int{4, 5, 6},
		},
	}
	assert.Equal(t, expected, c.envVarData)
}

func TestLoadYaml(t *testing.T) {
	opts := NewOption()
	opts.SetKnown("a")
	opts.SetKnown("b.a")
	opts.SetKnown("b.c")

	opts.AppendYamlFile(path.Join("fixtures", "basic.yaml"))

	conf, warnings, err := Load(opts)
	c := conf.(*config)
	assert.NoError(t, err)
	assert.Empty(t, warnings)

	expected := map[string]interface{}{
		"a": 21,
		"b": map[string]interface{}{
			"a": "test",
			"c": []interface{}{1, 2, 3}, // types from loaded YAML are not typed
		},
	}
	assert.Equal(t, expected, c.fileData)
}

func TestLoadMutipleYamls(t *testing.T) {
	opts := NewOption()
	opts.SetKnown("a")
	opts.SetKnown("b.a")
	opts.SetKnown("b.b")
	opts.SetKnown("b.c")

	opts.AppendYamlFile(path.Join("fixtures", "basic.yaml"))
	opts.AppendYamlFile(path.Join("fixtures", "extra.yaml"))

	conf, warnings, err := Load(opts)
	c := conf.(*config)
	assert.NoError(t, err)
	assert.Empty(t, warnings)

	expected := map[string]interface{}{
		"a": 22, // value overwritten by extra.yaml
		"b": map[string]interface{}{
			"a": "test",
			"b": map[interface{}]interface{}{"a": 1, "b": 2, "c": 3},
			"c": []interface{}{1, 2, 3}, // types from loaded YAML are not typed
		},
	}
	assert.Equal(t, expected, c.fileData)
}

func TestLoadYamlUnknownKey(t *testing.T) {
	opts := NewOption()
	opts.SetKnown("a")

	opts.AppendYamlFile(path.Join("fixtures", "basic.yaml"))

	conf, warnings, err := Load(opts)
	c := conf.(*config)
	assert.NoError(t, err)

	expected := []string{"unknown configuration setting 'b.a'", "unknown configuration setting 'b.c'"}
	sort.Strings(warnings)
	assert.Equal(t, expected, warnings)

	expectedData := map[string]interface{}{
		"a": 21,
	}
	assert.Equal(t, expectedData, c.fileData)
}

func TestLoadYamlError(t *testing.T) {
	opts := NewOption()
	opts.SetKnown("a")

	opts.AppendYamlFile(path.Join("fixtures", "does_not_exists.yaml"))

	_, warnings, err := Load(opts)
	assert.NoError(t, err)

	require.Len(t, warnings, 1)
	assert.True(t, strings.HasPrefix(warnings[0], "error reading configuration file "))
}

func TestLoadInvalidYaml(t *testing.T) {
	opts := NewOption()
	opts.SetKnown("a")

	opts.AppendYamlFile(path.Join("fixtures", "invalid.yaml"))

	_, _, err := Load(opts)
	assert.Error(t, err)
}

type user struct {
	Age  int
	Name string
}

// a: 1
// B:
//   C: 2
//   d: [1,2,3]
//   e:
//     F: "test"
//     G: "TEST"
// h: null
// i: "test"
// user:
//   info2:
//     - { "age": 1, "name": "test" }
//     - { "age": 2, "name": "test2" }

func TestFullLoading(t *testing.T) {
	opts := NewOption()

	// Setting known key without value
	opts.SetKnown("a")

	// Setting defaults
	opts.SetKnown("known_key_with_no_value")
	opts.SetDefault("b.c", 21)
	opts.SetDefault("b.d", []int{})
	opts.SetDefault("b.e.f", "")
	opts.SetDefault("b.e.g", "")
	opts.SetDefault("b.e.x", "")
	opts.SetDefault("h", 123)
	opts.SetDefault("i", "")
	opts.SetDefault("user.info", []user{})
	opts.SetDefault("user.info2", []user{})

	// setting env prefix
	opts.SetEnvPrefix("DD_")

	// setting an env alias
	opts.AddEnvAlias("user.info", "USERS_INFO")

	// loading a yaml file
	opts.AppendYamlFile("fixtures/full.yaml")

	// Adding an env transformer to load []user from JSON in env vars
	userTransformer := func(data string) interface{} {
		res := []user{}
		err := json.Unmarshal([]byte(data), &res)
		require.NoError(t, err)
		return res
	}
	opts.SetEnvKeyTransformer("user.info", userTransformer)
	opts.SetEnvKeyTransformer("user.info2", userTransformer)

	// filling env vars
	t.Setenv("DD_A", "21")
	t.Setenv("USERS_INFO", `[{"age": 123, "name": "data"}, {"age": 456, "name": "dog"}]`)

	c, warnings, err := Load(opts)
	require.NoError(t, err)
	assert.Empty(t, warnings)

	expected := map[string]interface{}{
		"a": "21", // data from env over file and default
		"b": map[string]interface{}{
			"c": 2, // value from file over default
			"d": []interface{}{1, 2, 3},
			"e": map[string]interface{}{
				"f": "test", // overwritten by config with capitalized key
				"g": "TEST", // overwritten by config
				"x": "",     // from default
			},
		},
		"h": nil,
		"i": "test",
		"user": map[string]interface{}{
			// data loaded from env alias + envKeyTransformer
			//
			// We have an issue with the type where envKeyTransformer returns a '[]user' but the data from
			// the YAML file return a []interface{}.
			"info": []user{
				user{Age: 123, Name: "data"},
				user{Age: 456, Name: "dog"},
			},
			// Error: this is not types since we don't enforce the type from the default over the loaded
			// data from the YAML.
			//
			// Should we support setting/getting struct from the configuration ?
			//    ie: should `SetDefault("users": []user{})` be valid ?
			"info2": []interface{}{
				map[interface{}]interface{}{"age": 1, "name": "test"},
				map[interface{}]interface{}{"age": 2, "name": "test2"},
			},
		},
	}

	conf := c.(*config)
	// fmt.Printf("\ndefault\n%+v\n\n", conf.defaultData)
	// fmt.Printf("\nfile\n%+v\n\n", conf.fileData)
	// fmt.Printf("\nenv\n%+v\n\n", conf.envVarData)
	// fmt.Printf("\nfinal\n%+v\n\n", conf.data)
	assert.Equal(t, expected, conf.data)
}
