// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewOption(t *testing.T) {
	opts := NewOption()

	require.NotNil(t, opts)
	assert.Equal(t, defaultKeyDelim, opts.keyDelim)
}

func assertKnown(t *testing.T, opts *Option, key string) {
	assert.Contains(t, opts.knownKeys, key)
}

func assertNotKnown(t *testing.T, opts *Option, key string) {
	assert.NotContains(t, opts.knownKeys, key)
}

func TestSetKeyDelim(t *testing.T) {
	opts := NewOption()
	opts.SetKeyDelim("-")
	assert.Equal(t, "-", opts.keyDelim)
}

func TestSetKnown(t *testing.T) {
	opts := NewOption()
	opts.SetDefault("test.a", 21)
	opts.SetDefault("TEST.B", "value")

	assertKnown(t, opts, "test.a")
	assertKnown(t, opts, "test.b")
	assertNotKnown(t, opts, "test.B")
}

func TestSetDefault(t *testing.T) {
	opts := NewOption()
	opts.SetDefault("test.a", 21)
	opts.SetDefault("test.B", "value")

	assert.Contains(t, opts.defaults, "test.a")
	// testing that lowercase is apply on keys
	require.Contains(t, opts.defaults, "test.b")
	assert.Equal(t, 21, opts.defaults["test.a"])
	require.NotContains(t, opts.defaults, "test.B")
	assert.Equal(t, "value", opts.defaults["test.b"])

	assertKnown(t, opts, "test.a")
	assertKnown(t, opts, "test.b")
	assertNotKnown(t, opts, "test.B")
}

func TestAddEnvAlias(t *testing.T) {
	opts := NewOption()
	opts.SetEnvPrefix("DD_")

	opts.AddEnvAlias("test.a", "TEST_A")
	opts.AddEnvAlias("TEST.B", "TEST_B")

	require.Contains(t, opts.envAliases, "DD_TEST_A")
	require.Contains(t, opts.envAliases, "DD_TEST_B")
	assert.Equal(t, "test.a", opts.envAliases["DD_TEST_A"])
	assert.Equal(t, "test.b", opts.envAliases["DD_TEST_B"])

	assertKnown(t, opts, "test.a")
	assertKnown(t, opts, "test.b")
	assertNotKnown(t, opts, "test.B")
}

func TestSetEnvKeyTransformer(t *testing.T) {
	opts := NewOption()
	opts.SetEnvPrefix("DD_")

	opts.SetEnvKeyTransformer("test.a", func(string) interface{} { return nil })
	opts.SetEnvKeyTransformer("TEST.B", func(string) interface{} { return nil })

	require.Contains(t, opts.envKeyTransformer, "test.a")
	require.Contains(t, opts.envKeyTransformer, "test.b")

	assertKnown(t, opts, "test.a")
	assertKnown(t, opts, "test.b")
	assertNotKnown(t, opts, "test.B")
}

func TestAppendYamlFile(t *testing.T) {
	opts := NewOption()
	opts.AppendYamlFile("file1.yaml", "file2.yaml")
	opts.AppendYamlFile("file3.yaml")

	assert.Equal(t, []string{"file1.yaml", "file2.yaml", "file3.yaml"}, opts.yamlFiles)
}
