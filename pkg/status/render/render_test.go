// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package render

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFormatHPAStatus(t *testing.T) {
	t.Run("valid JSON", func(t *testing.T) {
		validJSON := []byte(`{"key": "value"}`)
		result, err := FormatHPAStatus(validJSON)
		require.NoError(t, err)
		assert.Contains(t, result, "Custom Metrics Server")
	})

	t.Run("invalid JSON", func(t *testing.T) {
		invalidJSON := []byte(`{"key": "value"`)
		result, err := FormatHPAStatus(invalidJSON)
		require.NoError(t, err)
		assert.Contains(t, result, "Status render errors")
	})
}

func TestFormatMetadataMapCLI(t *testing.T) {
	t.Run("valid JSON", func(t *testing.T) {
		validJSON := []byte(`{"Errors": "some error"}`)
		result, err := FormatMetadataMapCLI(validJSON)
		require.NoError(t, err)
		assert.Contains(t, result, "some error")
	})

	t.Run("invalid JSON", func(t *testing.T) {
		invalidJSON := []byte(`{"Errors": "some error"`)
		result, err := FormatMetadataMapCLI(invalidJSON)
		require.NoError(t, err)
		assert.Contains(t, result, "Status render errors")
	})
}

func TestParseTemplate(t *testing.T) {
	data := map[string]interface{}{"key": "value"}

	t.Run("valid template", func(t *testing.T) {
		var b bytes.Buffer
		err := ParseTemplate(&b, "rendererrors.tmpl", data)
		require.NoError(t, err)
		assert.NotEmpty(t, b.String())
	})

	t.Run("invalid template", func(t *testing.T) {
		var b bytes.Buffer
		err := ParseTemplate(&b, "invalid.tmpl", data)
		assert.Error(t, err)
	})
}

func TestRenderErrors(t *testing.T) {
	t.Run("no errors", func(t *testing.T) {
		var b bytes.Buffer
		err := renderErrors(&b, nil)
		require.NoError(t, err)
		assert.Empty(t, strings.TrimSpace(b.String()))
	})

	t.Run("with errors", func(t *testing.T) {
		var b bytes.Buffer
		err := renderErrors(&b, []error{errors.New("test error")})
		require.NoError(t, err)
		assert.Contains(t, b.String(), "test error")
	})
}

func TestUnmarshalStatus(t *testing.T) {
	t.Run("valid JSON", func(t *testing.T) {
		validJSON := []byte(`{"key": "value"}`)
		stats, renderError, err := unmarshalStatus(validJSON)
		require.NoError(t, err)
		assert.Empty(t, renderError)
		assert.NotNil(t, stats)
		assert.Equal(t, map[string]interface{}{"key": "value"}, stats)
	})

	t.Run("invalid JSON", func(t *testing.T) {
		invalidJSON := []byte(`{"key": "value"`)
		stats, renderError, err := unmarshalStatus(invalidJSON)
		require.NoError(t, err)
		assert.NotEmpty(t, renderError)
		assert.Nil(t, stats)
	})
}
