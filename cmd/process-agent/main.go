// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//nolint:revive // TODO(PROC) Fix revive linter
package main

import (
	_ "net/http/pprof"
	"os"

	"github.com/DataDog/datadog-agent/cmd/internal/runcmd"
	"github.com/DataDog/datadog-agent/cmd/process-agent/command"
	"github.com/DataDog/datadog-agent/cmd/process-agent/subcommands"
	"github.com/DataDog/datadog-agent/pkg/util/flavor"

	_ "go.opentelemetry.io/collector/component"
	_ "go.opentelemetry.io/collector/config/configtelemetry"
	_ "go.opentelemetry.io/collector/confmap"
	_ "go.opentelemetry.io/collector/featuregate"
	_ "go.opentelemetry.io/collector/pdata/pcommon"
	_ "go.opentelemetry.io/collector/semconv/v1.6.1"
	_ "golang.org/x/sys/execabs"
)

// main is the main application entry point
func main() {
	flavor.SetFlavor(flavor.ProcessAgent)

	os.Args = command.FixDeprecatedFlags(os.Args, os.Stdout)

	rootCmd := command.MakeCommand(subcommands.ProcessAgentSubcommands(), command.UseWinParams, command.RootCmdRun)
	os.Exit(runcmd.Run(rootCmd))
}
