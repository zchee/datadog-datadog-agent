// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package amqp

import (
	"fmt"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"

	httpUtils "github.com/DataDog/datadog-agent/pkg/network/protocols/http/testutil"
	protocolsUtils "github.com/DataDog/datadog-agent/pkg/network/protocols/testutil"
)

const (
	// User is the user to use for authentication
	User = "guest"
	// Pass is the password to use for authentication
	Pass = "guest"

	// AmqpPlaintext is a flag to indicate that the server should be started with plaintext
	AmqpPlaintext = false
	// AmqpTLS is a flag to indicate that the server should be started with TLS
	AmqpTLS = true
)

// RunServer runs an AMQP server in a docker container.
func RunServer(t testing.TB, serverAddr, serverPort string, withTLS bool) error {
	t.Helper()

	var env []string
	var startupRegexp *regexp.Regexp
	if withTLS {
		env, startupRegexp = tlsConfig(t, serverAddr, serverPort)
	} else {
		env, startupRegexp = plaintextConfig(t, serverAddr, serverPort)
	}
	dir, _ := httpUtils.CurDir()

	return protocolsUtils.RunDockerServer(t, "amqp", dir+"/testdata/docker-compose.yml", env, startupRegexp, protocolsUtils.DefaultTimeout, 3)
}

// commonConfig returns the common environment variables for the amqp server,
// independently of whether or not the server uses TLS or not..
func commonConfig(serverAddr, serverPort string) []string {
	return []string{
		"AMQP_ADDR=" + serverAddr,
		"AMQP_PORT=" + serverPort,
		"USER=" + User,
		"PASS=" + Pass,
	}
}

// plaintextConfig returns the configuration environment variables, as well as
// the startup regexp to check for proper initialization of the plaintext AMQP
// server.
func plaintextConfig(t testing.TB, serverAddr, serverPort string) ([]string, *regexp.Regexp) {
	t.Helper()

	env := commonConfig(serverAddr, serverPort)
	startupRegexp := regexp.MustCompile(fmt.Sprintf(".*started TCP listener on .*%s.*", serverPort))

	return append(env, "ENCRYPTION_POLICY=plaintext"), startupRegexp
}

// tlsConfig returns the configuration environment variables, as well as
// the startup regexp to check for proper initialization of the TLS-enabled AMQP
// server.
func tlsConfig(t testing.TB, serverAddr, serverPort string) ([]string, *regexp.Regexp) {
	t.Helper()

	env := commonConfig(serverAddr, serverPort)
	cert, _, err := httpUtils.GetCertsPaths()
	require.NoError(t, err)
	certsDir := filepath.Dir(cert)
	startupRegexp := regexp.MustCompile(fmt.Sprintf(".*started TLS \\(SSL\\) listener on .*%s.*", serverPort))

	return append(env, "CERTS_PATH="+certsDir, "ENCRYPTION_POLICY=tls"), startupRegexp
}
