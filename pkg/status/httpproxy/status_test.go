// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package httpproxy

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/DataDog/datadog-agent/pkg/config/mock"
)

func TestGetProvider(t *testing.T) {
	conf := mock.New(t)
	conf.SetWithoutSource("no_proxy_nonexact_match", false)
	provider := GetProvider(conf)
	assert.NotNil(t, provider)

	conf.SetWithoutSource("no_proxy_nonexact_match", true)
	provider = GetProvider(conf)
	assert.Nil(t, provider)
}

func TestProviderJSON(t *testing.T) {
	p := Provider{}
	stats := make(map[string]interface{})
	err := p.JSON(false, stats)
	require.NoError(t, err)

	if assert.Contains(t, stats, "TransportWarnings") {
		assert.Empty(t, stats["TransportWarnings"])
	}
	if assert.Contains(t, stats, "NoProxyIgnoredWarningMap") {
		assert.Empty(t, stats["NoProxyIgnoredWarningMap"])
	}
	if assert.Contains(t, stats, "NoProxyUsedInFuture") {
		assert.Empty(t, stats["NoProxyUsedInFuture"])
	}
	if assert.Contains(t, stats, "NoProxyChanged") {
		assert.Empty(t, stats["NoProxyChanged"])
	}
}

func TestProviderText(t *testing.T) {
	p := Provider{}
	var buffer bytes.Buffer
	err := p.Text(false, &buffer)
	require.NoError(t, err)
	assert.Equal(t, strings.TrimSpace(buffer.String()), "No Transport Proxy Warnings")
}

func TestProviderHTML(t *testing.T) {
	p := Provider{}
	var buffer bytes.Buffer
	err := p.HTML(false, &buffer)
	require.NoError(t, err)
	assert.Empty(t, strings.TrimSpace(buffer.String()))
}
