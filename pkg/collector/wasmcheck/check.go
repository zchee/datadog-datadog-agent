package wasmcheck

import (
	"context"
	"fmt"
	"time"

	"github.com/tetratelabs/wazero/api"
	"gopkg.in/yaml.v2"

	"github.com/DataDog/datadog-agent/comp/core/autodiscovery/integration"
	"github.com/DataDog/datadog-agent/pkg/aggregator/sender"
	"github.com/DataDog/datadog-agent/pkg/collector/check/defaults"
	checkid "github.com/DataDog/datadog-agent/pkg/collector/check/id"
	"github.com/DataDog/datadog-agent/pkg/collector/check/stats"
	"github.com/DataDog/datadog-agent/pkg/config"
	"github.com/DataDog/datadog-agent/pkg/config/utils"
	"github.com/DataDog/datadog-agent/pkg/diagnose/diagnosis"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

type wasmFunc struct {
	check  api.Function
	malloc api.Function
	free   api.Function
}

type wasmCheck struct {
	ctx                context.Context
	funcs              wasmFunc
	wasmModule         api.Module
	senderManager      sender.SenderManager
	id                 checkid.ID
	ModuleName         string
	interval           time.Duration
	lastWarnings       []error
	source             string
	telemetry          bool // whether or not the telemetry is enabled for this check
	initConfig         string
	instanceConfig     string
	wasmInstanceConfig wasmString
}

type instanceConfig struct {
	JSONData string `yaml:"jsonData"`
}

// NewwasmCheck conveniently creates a wasmCheck instance
func newWasmCheck(ctx context.Context, id checkid.ID, name string, wasmModule api.Module, initConfig initConfig) (*wasmCheck, error) {

	checkFunction := wasmModule.ExportedFunction("check")
	if checkFunction == nil {
		return nil, fmt.Errorf("failed to find wasm function \"check\"")
	}

	// // These are undocumented, but exported. See tinygo-org/tinygo#2788
	malloc := wasmModule.ExportedFunction(initConfig.AllocateFunc)
	free := wasmModule.ExportedFunction(initConfig.FreeFunc)

	if malloc == nil {
		return nil, fmt.Errorf("failed to find wasm function \"malloc\"")
	}

	if free == nil {
		return nil, fmt.Errorf("failed to find wasm function \"free\"")
	}

	check := &wasmCheck{
		ctx:          ctx,
		funcs:        wasmFunc{check: checkFunction, malloc: malloc, free: free},
		wasmModule:   wasmModule,
		ModuleName:   name,
		interval:     defaults.DefaultCheckInterval,
		lastWarnings: []error{},
		telemetry:    utils.IsCheckTelemetryEnabled(name, config.Datadog),
		id:           id,
	}
	// TODO runtime.SetFinalizer(pyCheck, wasmCheckFinalizer)

	return check, nil
}

func (c *wasmCheck) runCheck(_ bool) error {

	//TODO better implement this
	_, err := c.funcs.check.Call(c.ctx, c.wasmInstanceConfig.ptr, c.wasmInstanceConfig.size)
	if err != nil {
		log.Errorf("failed to invoke \"check\": %v", err)
	}

	sender, err := c.senderManager.GetSender(c.id)
	if err != nil {
		return err
	}
	sender.Commit()

	return nil
}

// Run a wasm check
func (c *wasmCheck) Run() error {
	return c.runCheck(true)
}

// RunSimple runs a wasm check without sending data to the aggregator
func (c *wasmCheck) RunSimple() error {
	return c.runCheck(false)
}

// Stop does nothing
func (c *wasmCheck) Stop() {}

// Cancel signals to a wasm check that he can free all internal resources and
// deregisters the sender
func (c *wasmCheck) Cancel() {
	// TODO implement Cancel mechanism
}

// String representation (for debug and logging)
func (c *wasmCheck) String() string {
	return c.ModuleName
}

// Version returns the version of the check if load from a wasm wheel
func (c *wasmCheck) Version() string {
	return ""
}

// IsTelemetryEnabled returns if the telemetry is enabled for this check
func (c *wasmCheck) IsTelemetryEnabled() bool {
	return c.telemetry
}

// ConfigSource returns the source of the configuration for this check
func (c *wasmCheck) ConfigSource() string {
	return c.source
}

// InitConfig returns the init_config configuration for the check.
func (c *wasmCheck) InitConfig() string {
	return c.initConfig
}

// InstanceConfig returns the instance configuration for the check.
func (c *wasmCheck) InstanceConfig() string {
	return c.instanceConfig
}

// GetWarnings grabs the last warnings from the struct
func (c *wasmCheck) GetWarnings() []error {
	warnings := c.lastWarnings
	c.lastWarnings = []error{}
	return warnings
}

// Configure the wasm check from YAML data
//
//nolint:revive // TODO(AML) Fix revive linter
func (c *wasmCheck) Configure(senderManager sender.SenderManager, integrationConfigDigest uint64, data integration.Data, initConfig integration.Data, source string) error {
	c.senderManager = senderManager

	commonGlobalOptions := integration.CommonGlobalConfig{}
	if err := yaml.Unmarshal(initConfig, &commonGlobalOptions); err != nil {
		log.Errorf("invalid init_config section for check %s: %s", string(c.id), err)
		return err
	}

	// Set service for this check
	if len(commonGlobalOptions.Service) > 0 {
		s, err := c.senderManager.GetSender(c.id)
		if err != nil {
			log.Errorf("failed to retrieve a sender for check %s: %s", string(c.id), err)
		} else {
			s.SetCheckService(commonGlobalOptions.Service)
		}
	}

	commonOptions := integration.CommonInstanceConfig{}
	if err := yaml.Unmarshal(data, &commonOptions); err != nil {
		log.Errorf("invalid instance section for check %s: %s", string(c.id), err)
		return err
	}

	// See if a collection interval was specified
	if commonOptions.MinCollectionInterval > 0 {
		c.interval = time.Duration(commonOptions.MinCollectionInterval) * time.Second
	}

	// Disable default hostname if specified
	if commonOptions.EmptyDefaultHostname {
		s, err := c.senderManager.GetSender(c.id)
		if err != nil {
			log.Errorf("failed to retrieve a sender for check %s: %s", string(c.id), err)
		} else {
			s.DisableDefaultHostname(true)
		}
	}

	// Set configured service for this check, overriding the one possibly defined globally
	if len(commonOptions.Service) > 0 {
		s, err := c.senderManager.GetSender(c.id)
		if err != nil {
			log.Errorf("failed to retrieve a sender for check %s: %s", string(c.id), err)
		} else {
			s.SetCheckService(commonOptions.Service)
		}
	}

	// wasmInitConfig, err := c.TrackedWasmString(string(initConfig))
	// if err != nil {
	// 	log.Errorf("unable to allocate memory for initConfig for check %s: %s", string(c.id), err)
	// 	return err
	// }
	// wasmData, err := c.TrackedWasmString(string(data))
	// if err != nil {
	// 	log.Errorf("unable to allocate memory for data for check %s: %s", string(c.id), err)
	// 	return err
	// }
	// wasmId, err := c.TrackedWasmString(string(c.id))
	// if err != nil {
	// 	log.Errorf("unable to allocate memory for id for check %s: %s", string(c.id), err)
	// 	return err
	// }

	instanceConfig := instanceConfig{}
	if err := yaml.Unmarshal(data, &instanceConfig); err != nil {
		log.Errorf("invalid instanceConfig section for check %s: %s", string(c.id), err)
		return err
	}

	wasmJSON, err := c.TrackedWasmString(instanceConfig.JSONData)
	if err != nil {
		log.Errorf("unable to allocate memory for id for check %s: %s", string(c.id), err)
		return err
	}

	c.wasmInstanceConfig = wasmJSON
	// TODO implement here interface between wasm and checks (return and parameters)

	return nil
}

// GetSenderStats returns the stats from the last run of the check
func (c *wasmCheck) GetSenderStats() (stats.SenderStats, error) {
	sender, err := c.senderManager.GetSender(c.ID())
	if err != nil {
		return stats.SenderStats{}, fmt.Errorf("Failed to retrieve a Sender instance: %v", err)
	}
	return sender.GetSenderStats(), nil
}

// Interval returns the scheduling time for the check
func (c *wasmCheck) Interval() time.Duration {
	return c.interval
}

// ID returns the ID of the check
func (c *wasmCheck) ID() checkid.ID {
	return c.id
}

// GetDiagnoses returns the diagnoses cached in last run or diagnose explicitly
func (c *wasmCheck) GetDiagnoses() ([]diagnosis.Diagnosis, error) {
	// TODO need impl
	return nil, nil
}

type wasmString struct {
	ptr  uint64
	size uint64
}

func (c *wasmCheck) TrackedWasmString(str string) (wasmString, error) {
	var wasmStr wasmString

	wasmStr.size = uint64(len(str))

	results, err := c.funcs.malloc.Call(c.ctx, wasmStr.size)
	if err != nil {
		return wasmStr, err
	}
	wasmStr.ptr = results[0]
	// This pointer is managed by TinyGo, but TinyGo is unaware of external usage.
	// So, we have to free it when finished
	// defer c.funcs.free.Call(c.ctx, wasmStr.ptr)

	// TODO free memoery allocation

	// The pointer is a linear memory offset, which is where we write the name.
	if !c.wasmModule.Memory().Write(uint32(wasmStr.ptr), []byte(str)) {
		return wasmStr, fmt.Errorf("Memory.Write(%d, %d) out of range of memory size %d",
			wasmStr.ptr, wasmStr.size, c.wasmModule.Memory().Size())
	}

	return wasmStr, nil
}
