// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package testutil

import (
	"path/filepath"
	"os/exec"
	"testing"

	httpUtils "github.com/DataDog/datadog-agent/pkg/network/protocols/http/testutil"
	"github.com/stretchr/testify/require"
)

const scriptName = "create_docker_certs_volume.sh"

// EnsureCertsDockerVolume ensures the docker volume "test_tls_certs"
// exists. If the volume does not exists, it creates it using
// pregenerated certificates.
func EnsureCertsDockerVolume(t testing.TB) {
	t.Helper()

	curDir, err := httpUtils.CurDir()
	require.NoError(t, err)

	scriptPath := filepath.Join(curDir, scriptName)

	cert, _, err := httpUtils.GetCertsPaths()
	require.NoError(t, err)
	certsDir := filepath.Dir(cert)

	c := exec.Command(scriptPath, certsDir)
	require.NoError(t, c.Run())
}
