// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package dpkg

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsInstalled(t *testing.T) {
	tmpDir := t.TempDir()
	oldPath := os.Getenv("PATH")
	os.Setenv("PATH", tmpDir)
	defer os.Setenv("PATH", oldPath)

	isInstalled, err := IsInstalled(context.Background())
	assert.NoError(t, err)
	assert.False(t, isInstalled)

	err = os.WriteFile(filepath.Join(tmpDir, "dpkg"), []byte(`#!/bin/sh`), 0755)
	assert.NoError(t, err)

	isInstalled, err = IsInstalled(context.Background())
	assert.NoError(t, err)
	assert.True(t, isInstalled)
}
