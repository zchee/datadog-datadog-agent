// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf

// Package gpu contains implementation for the gpu-monitoring module
package gpu

import (
	"github.com/DataDog/datadog-agent/pkg/ebpf/bytecode/runtime"
	"github.com/DataDog/datadog-agent/pkg/gpu/config"
	"github.com/DataDog/datadog-agent/pkg/process/statsd"
)

//go:generate $GOPATH/bin/include_headers pkg/gpu/ebpf/c/runtime/gpu.c pkg/ebpf/bytecode/build/runtime/gpu.c pkg/ebpf/c pkg/gpu/ebpf/c/runtime pkg/gpu/ebpf/c
//go:generate $GOPATH/bin/integrity pkg/ebpf/bytecode/build/runtime/gpu.c pkg/ebpf/bytecode/runtime/gpu.go runtime

func getRuntimeCompiledGPUMonitoring(config *config.Config) (runtime.CompiledOutput, error) {
	return runtime.Gpu.Compile(&config.Config, getCFlags(config), statsd.Client)
}

func getCFlags(config *config.Config) []string {
	cflags := []string{"-g"}

	if config.BPFDebug {
		cflags = append(cflags, "-DDEBUG=1")
	}
	return cflags
}