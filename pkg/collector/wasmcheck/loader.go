// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package wasmcheck

import (
	"context"
	"fmt"
	"os"
	"path"
	"strings"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"gopkg.in/yaml.v2"

	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"

	"github.com/DataDog/datadog-agent/comp/core/autodiscovery/integration"
	"github.com/DataDog/datadog-agent/pkg/aggregator/sender"
	"github.com/DataDog/datadog-agent/pkg/collector/check"
	checkid "github.com/DataDog/datadog-agent/pkg/collector/check/id"
	"github.com/DataDog/datadog-agent/pkg/collector/loaders"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

// WasmCheckLoader is a specific loader for checks living in this package
type WasmCheckLoader struct {
	wasmRuntime    wazero.Runtime
	checkFunctions api.Module
	ctx            context.Context
	senderManager  sender.SenderManager
}

type initConfig struct {
	LoaderName   string `yaml:"loader"`
	WasmPath     string `yaml:"path"`
	AllocateFunc string `yaml:"allocate_func"`
	FreeFunc     string `yaml:"free_func"`
}

func fromWasmString(m api.Memory, ptr, size uint32) (string, error) {
	// The pointer is a linear memory offset, which is where we write the name.
	if bytes, ok := m.Read(ptr, size); !ok {
		return "", fmt.Errorf("Memory.Read(%d, %d) out of range of memory size %d",
			ptr, size, m.Size())
	} else {
		return string(bytes), nil
	}
}

// NewWasmCheckLoader creates a loader for go checks
func NewWasmCheckLoader(senderManager sender.SenderManager) (*WasmCheckLoader, error) {
	ctx := context.Background()
	r := wazero.NewRuntime(ctx)

	_, err := r.NewHostModuleBuilder("env").
		NewFunctionBuilder().
		WithFunc(func(ctx context.Context, m api.Module, v float64, pMetric, sMetric, pHostname, sHostname, pTags, sTags uint32) {
			sender, err := senderManager.GetSender(checkid.ID(m.Name()))
			if err != nil {
				fmt.Println(err.Error())
			}
			mem := m.Memory()

			metric, err := fromWasmString(mem, pMetric, sMetric)
			if err != nil {
				fmt.Println(err.Error())
			}
			hostname, err := fromWasmString(mem, pHostname, sHostname)
			if err != nil {
				fmt.Println(err.Error())
			}
			tags, err := fromWasmString(mem, pTags, sTags)
			if err != nil {
				fmt.Println(err.Error())
			}

			sender.Gauge(metric, v, hostname, []string{tags})
		}).
		Export("gauge").
		Instantiate(ctx)

	// Note: testdata/greet.go doesn't use WASI, but TinyGo needs it to
	// implement functions such as panic.
	wasi_snapshot_preview1.MustInstantiate(ctx, r)

	if err != nil {
		log.Errorf(err.Error())
	}

	return &WasmCheckLoader{
		wasmRuntime:   r,
		ctx:           ctx,
		senderManager: senderManager,
	}, nil
}

// Name return returns Go loader name
func (l WasmCheckLoader) Name() string {
	return "wasm"
}

// Load returns a Go check
func (l *WasmCheckLoader) Load(senderManger sender.SenderManager, config integration.Config, instance integration.Data) (check.Check, error) {
	var c check.Check

	initConfig := initConfig{}

	err := yaml.Unmarshal(config.InitConfig, &initConfig)
	if err != nil {
		return nil, fmt.Errorf("Unable to parse instance config for check `%s`: %v", config.Name, instance)
	}

	if initConfig.LoaderName != "wasm" {
		return nil, fmt.Errorf("Check %s not implemented in wasm", config.Name)
	}

	if initConfig.WasmPath == "" {
		return nil, fmt.Errorf("Check %s is missing init_config.path paramater", config.Name)
	}

	pathRoot := config.Source

	if strings.HasPrefix(config.Source, "file:") {
		pathRoot = strings.TrimPrefix(path.Dir(config.Source), "file:")
	}

	wasmBinary, err := os.ReadFile(path.Join(pathRoot, initConfig.WasmPath))
	if err != nil {
		return nil, fmt.Errorf("Failed to read wasm file: %v", err)
	}

	// Compile the Wasm binary once so that we can skip the entire compilation time during instantiation.
	compiledWasm, err := l.wasmRuntime.CompileModule(l.ctx, wasmBinary)
	if err != nil {
		return nil, fmt.Errorf("failed to compile Wasm binary: %v", err)
	}

	id := checkid.BuildID(config.Name, config.FastDigest(), instance, config.InitConfig)

	// Instantiate a new Wasm module from the already compiled `compiledWasm`.
	wasmModule, err := l.wasmRuntime.InstantiateModule(l.ctx, compiledWasm, wazero.NewModuleConfig().WithName(string(id)))
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate wasm Module: %v", err)
	}

	c, err = newWasmCheck(l.ctx, id, config.Name, wasmModule, initConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create WASM Check: %v", err)
	}
	err = c.Configure(senderManger, config.FastDigest(), instance, config.InitConfig, config.Source)
	if err != nil {
		return c, err
	}

	return c, nil
}

func (l *WasmCheckLoader) String() string {
	return "Wasm Check Loader"
}

func init() {
	factory := func(s sender.SenderManager) (check.Loader, error) {
		return NewWasmCheckLoader(s)
	}

	loaders.RegisterLoader(40, factory)
}
