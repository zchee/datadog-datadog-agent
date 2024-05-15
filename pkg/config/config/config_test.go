// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewConfig(t *testing.T) {
	opts := NewOption()
	c := newConfig(opts)
	assert.Equal(t, defaultKeyDelim, c.keyDelim)

	opts.SetKeyDelim("-")
	c = newConfig(opts)
	assert.Equal(t, "-", c.keyDelim)
}
