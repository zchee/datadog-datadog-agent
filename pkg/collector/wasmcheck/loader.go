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
	"gopkg.in/yaml.v2"

	"github.com/DataDog/datadog-agent/comp/core/autodiscovery/integration"
	"github.com/DataDog/datadog-agent/pkg/aggregator/sender"
	"github.com/DataDog/datadog-agent/pkg/collector/check"
	"github.com/DataDog/datadog-agent/pkg/collector/loaders"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

// WasmCheckLoader is a specific loader for checks living in this package
type WasmCheckLoader struct {
	wasmRuntime wazero.Runtime
	ctx         context.Context
}

type initConfig struct {
	LoaderName string `yaml:"loader"`
	WasmPath   string `yaml:"path"`
}

// NewWasmCheckLoader creates a loader for go checks
func NewWasmCheckLoader() (*WasmCheckLoader, error) {
	ctx := context.Background()
	return &WasmCheckLoader{
		wasmRuntime: wazero.NewRuntime(ctx),
		ctx:         ctx,
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
		log.Warnf("Unable to parse instance config for check `%s`: %v", config.Name, instance)
		return nil, err
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
		log.Errorf("Failed to read wasm file: %v", err)
	}

	// Compile the Wasm binary once so that we can skip the entire compilation time during instantiation.
	compiledWasm, err := l.wasmRuntime.CompileModule(l.ctx, wasmBinary)
	if err != nil {
		log.Errorf("failed to compile Wasm binary: %v", err)
	}

	// Instantiate a new Wasm module from the already compiled `compiledWasm`.
	wasmInstance, err := l.wasmRuntime.InstantiateModule(l.ctx, compiledWasm, wazero.NewModuleConfig().WithName(""))
	if err != nil {
		log.Errorf("failed to instantiate %v", err)
	}

	checkFunction := wasmInstance.ExportedFunction("check")
	if checkFunction == nil {
		log.Errorf("failed to find wasm function \"check\"", err)
	}

	c = newWasmCheck(l.ctx, checkFunction, config.Name)

	// if err := c.Configure(senderManger, config.FastDigest(), instance, config.InitConfig, config.Source); err != nil {
	// 	if errors.Is(err, check.ErrSkipCheckInstance) {
	// 		return c, err
	// 	}
	// 	log.Errorf("core.loader: could not configure check %s: %s", c, err)
	// 	msg := fmt.Sprintf("Could not configure check %s: %s", c, err)
	// 	return c, fmt.Errorf(msg)
	// }

	return c, nil
}

func (l *WasmCheckLoader) String() string {
	return "Wasm Check Loader"
}

func init() {
	factory := func(sender.SenderManager) (check.Loader, error) {
		return NewWasmCheckLoader()
	}

	loaders.RegisterLoader(40, factory)
}
