// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package main provides a unix transparent proxy server that can be used for testing.
package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/DataDog/datadog-agent/pkg/network/tracer/testutil/proxy"
)

func main() {
	// Define command-line flags
	var remoteAddr string
	var unixPath string
	var logPath string
	var testName string
	var useTLS bool
	var useControl bool

	flag.StringVar(&remoteAddr, "remote", "", "Remote server address to forward connections to")
	flag.StringVar(&unixPath, "unix", "/tmp/transparent.sock", "A local unix socket to listen on")
	flag.StringVar(&logPath, "log", "", "Log file")
	// Visible in the log as part of the command line
	flag.StringVar(&testName, "name", "", "Test name")
	flag.BoolVar(&useTLS, "tls", false, "Use TLS to connect to the remote server")
	flag.BoolVar(&useControl, "control", false, "Use control messages")

	// Parse command-line flags
	flag.Parse()

	if logPath != "" {
		log.Println("Logging to", logPath)

		// Append instead of truncating so that it doesn't get cleared every
		// time the proxy is restarted, to make it easier to use for debugging.
		logFile, err := os.OpenFile(logPath, os.O_APPEND|os.O_RDWR|os.O_CREATE, 0644)
		if err != nil {
			log.Panic(err)
		}
		defer logFile.Close()

		log.SetOutput(logFile)
	}

	log.Println("Command line:", os.Args)

	done := make(chan os.Signal, 1)
	signal.Notify(done, syscall.SIGINT)

	srv := proxy.NewUnixTransparentProxyServer(unixPath, remoteAddr, useTLS, useControl)
	defer srv.Stop()

	if err := srv.Run(); err != nil {
		log.Fatal(err)
	}

	<-done
}
