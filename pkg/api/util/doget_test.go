// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package util

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cihub/seelog"

	configmock "github.com/DataDog/datadog-agent/pkg/config/mock"
	"github.com/DataDog/datadog-agent/pkg/config/model"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

func makeTestServer(t *testing.T, handler func(w http.ResponseWriter, r *http.Request)) *httptest.Server {
	server := httptest.NewServer(http.HandlerFunc(handler))
	t.Cleanup(server.Close)
	return server
}

func TestDoGet(t *testing.T) {
	t.Run("simple request", func(t *testing.T) {
		handler := func(w http.ResponseWriter, _ *http.Request) {
			w.Write([]byte("test"))
		}
		server := makeTestServer(t, http.HandlerFunc(handler))
		data, err := DoGet(server.Client(), server.URL, CloseConnection)
		require.NoError(t, err)
		require.Equal(t, "test", string(data))
	})

	t.Run("error response", func(t *testing.T) {
		handler := func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}
		server := makeTestServer(t, http.HandlerFunc(handler))
		_, err := DoGetWithOptions(server.Client(), server.URL, &ReqOptions{})
		require.Error(t, err)
	})

	t.Run("url error", func(t *testing.T) {
		_, err := DoGetWithOptions(http.DefaultClient, " http://localhost", &ReqOptions{})
		require.Error(t, err)
	})

	t.Run("request error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
		server.Close()

		_, err := DoGetWithOptions(server.Client(), server.URL, &ReqOptions{})
		require.Error(t, err)
	})

	t.Run("check auth token", func(t *testing.T) {
		handler := func(w http.ResponseWriter, r *http.Request) {
			require.Equal(t, "Bearer mytoken", r.Header.Get("Authorization"))
			w.WriteHeader(http.StatusOK)
		}
		server := makeTestServer(t, http.HandlerFunc(handler))

		options := &ReqOptions{Authtoken: "mytoken"}
		data, err := DoGetWithOptions(server.Client(), server.URL, options)
		require.NoError(t, err)
		require.Empty(t, data)
	})

	t.Run("check global auth token", func(t *testing.T) {
		handler := func(w http.ResponseWriter, r *http.Request) {
			require.Equal(t, "Bearer 0123456789abcdef0123456789abcdef", r.Header.Get("Authorization"))
			w.WriteHeader(http.StatusOK)
		}
		server := makeTestServer(t, http.HandlerFunc(handler))

		cfg := model.NewConfig("datadog", "test", strings.NewReplacer("_", "."))
		dir := t.TempDir()
		authTokenPath := dir + "/auth_token"
		err := os.WriteFile(authTokenPath, []byte("0123456789abcdef0123456789abcdef"), 0644)
		require.NoError(t, err)
		cfg.SetWithoutSource("auth_token_file_path", authTokenPath)
		SetAuthToken(cfg)

		options := &ReqOptions{}
		data, err := DoGetWithOptions(server.Client(), server.URL, options)
		require.NoError(t, err)
		require.Empty(t, data)
	})

	t.Run("context cancel", func(t *testing.T) {
		handler := func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}
		server := makeTestServer(t, http.HandlerFunc(handler))

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		options := &ReqOptions{Ctx: ctx}
		_, err := DoGetWithOptions(server.Client(), server.URL, options)
		require.Error(t, err)
	})
}

// setupMockLogger initializes and sets up a mock logger for testing purposes.
// It returns a buffer that captures the log output and an error if any occurs
// during the setup process.
//
// Returns:
// - *bytes.Buffer: A buffer that captures the log output.
// - error: An error if any occurs during the setup process.
func setupMockLogger(t *testing.T) (*bytes.Buffer, error) {
	innerB := bytes.NewBuffer(make([]byte, 0, 1024))
	b := bufio.NewWriter(innerB)

	bufferedWriter, err := seelog.NewBufferedWriter(b, 1024, 0)
	require.NoError(t, err)
	formatter, err := seelog.NewFormatter("%Level %Msg %File%n")
	require.NoError(t, err)
	root, err := seelog.NewSplitDispatcher(formatter, []interface{}{bufferedWriter})
	require.NoError(t, err)
	constraints, err := seelog.NewMinMaxConstraints(seelog.TraceLvl, seelog.CriticalLvl)
	require.NoError(t, err)
	specificConstraints, err := seelog.NewListConstraints([]seelog.LogLevel{seelog.InfoLvl, seelog.ErrorLvl})
	require.NoError(t, err)
	ex, err := seelog.NewLogLevelException("*", "*main.go", specificConstraints)
	require.NoError(t, err)
	exceptions := []*seelog.LogLevelException{ex}

	logger := seelog.NewAsyncLoopLogger(seelog.NewLoggerConfig(constraints, exceptions, root))

	seelog.ReplaceLogger(logger)
	log.SetupLogger(logger, "trace")

	return innerB, nil
}

// This test check that NewDialBookBuilder return an error when required config field are not set
func TestResolver(t *testing.T) {

	t.Run("mocking helper", func(t *testing.T) {
		handler := func(w http.ResponseWriter, _ *http.Request) {
			w.Write([]byte("test"))
		}
		server := makeTestServer(t, http.HandlerFunc(handler))

		// Overriding cmd host port with test server values
		cfg := configmock.New(t)
		host, port, err := net.SplitHostPort(server.Listener.Addr().String())
		require.NoError(t, err)
		cfg.SetWithoutSource("cmd_host", host)
		cfg.SetWithoutSource("cmd_port", port)

		client := GetClient(WithNoVerify())

		data, err := DoGet(client, fmt.Sprintf("http://%v", CoreCmd), CloseConnection)
		require.NoError(t, err)
		require.Equal(t, "test", string(data))
	})

	// This test check that unknown domain name are bypassed and logged
	t.Run("unknown address", func(t *testing.T) {
		loggerWritter, err := setupMockLogger(t)
		require.NoError(t, err)

		client := GetClient(WithNoVerify())

		handler := func(w http.ResponseWriter, _ *http.Request) {
			w.Write([]byte("test"))
		}
		server := makeTestServer(t, http.HandlerFunc(handler))
		data, err := DoGet(client, server.URL, CloseConnection)
		require.NoError(t, err)
		require.Equal(t, "test", string(data))

		seelog.Flush()

		require.Contains(t, loggerWritter.String(), "address not registered in the Agent name resolver")
	})

}
