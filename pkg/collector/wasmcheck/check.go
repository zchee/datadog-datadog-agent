package wasmcheck

import (
	"context"
	"fmt"
	"time"

	"github.com/tetratelabs/wazero/api"

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

// SafeSender implements sender.Sender, wrapping the methods to provide
// some additional safety checks.
//
// In particular, the methods taking `tags []string` are wrapped to copy the
// slice, as the aggregator may modify it in-place.
type safeSender struct {
	sender.Sender
}

var _ sender.Sender = &safeSender{}

func newSafeSender(sender sender.Sender) sender.Sender {
	return &safeSender{Sender: sender}
}

type wasmFunc struct {
	check  api.Function
	malloc api.Function
	free   api.Function
}

type wasmCheck struct {
	ctx            context.Context
	funcs          wasmFunc
	wasmModule     api.Module
	senderManager  sender.SenderManager
	id             checkid.ID
	ModuleName     string
	interval       time.Duration
	lastWarnings   []error
	source         string
	telemetry      bool // whether or not the telemetry is enabled for this check
	initConfig     string
	instanceConfig string
}

// NewwasmCheck conveniently creates a wasmCheck instance
func newWasmCheck(ctx context.Context, id checkid.ID, name string, wasmModule api.Module) *wasmCheck {

	checkFunction := wasmModule.ExportedFunction("check")
	if checkFunction == nil {
		log.Errorf("failed to find wasm function \"check\"")
	}

	// // These are undocumented, but exported. See tinygo-org/tinygo#2788
	malloc := wasmModule.ExportedFunction("malloc")
	free := wasmModule.ExportedFunction("free")

	check := &wasmCheck{
		ctx:          ctx,
		funcs:        wasmFunc{check: checkFunction, malloc: malloc, free: free},
		wasmModule:   wasmModule,
		ModuleName:   name,
		interval:     defaults.DefaultCheckInterval,
		lastWarnings: []error{},
		telemetry:    utils.IsCheckTelemetryEnabled(name, config.Datadog),
	}
	// TODO runtime.SetFinalizer(pyCheck, wasmCheckFinalizer)

	return check
}

// GetSender gets the object to which metrics for this check should be sent.
//
// This is a "safe" sender, specialized to avoid some common errors, at a very
// small cost to performance.  Performance-sensitive checks can use GetRawSender()
// to avoid this performance cost, as long as they are careful to avoid errors.
//
// See `safesender.go` for details on the managed errors.
func (c *wasmCheck) GetSender() (sender.Sender, error) {
	sender, err := c.GetRawSender()
	if err != nil {
		return nil, err
	}
	return newSafeSender(sender), err
}

// GetRawSender is similar to GetSender, but does not provide the safety wrapper.
func (c *wasmCheck) GetRawSender() (sender.Sender, error) {
	return c.senderManager.GetSender(c.ID())
}

func (c *wasmCheck) runCheck(commitMetrics bool) error {

	name := `{"name": "maxime"}`
	nameSize := uint64(len(name))
	// Instead of an arbitrary memory offset, use TinyGo's allocator. Notice
	// there is nothing string-specific in this allocation function. The same
	// function could be used to pass binary serialized data to Wasm.
	results, err := c.funcs.malloc.Call(c.ctx, nameSize)
	if err != nil {
		log.Errorf(err.Error())
	}
	namePtr := results[0]
	// This pointer is managed by TinyGo, but TinyGo is unaware of external usage.
	// So, we have to free it when finished
	defer c.funcs.free.Call(c.ctx, namePtr)

	// The pointer is a linear memory offset, which is where we write the name.
	if !c.wasmModule.Memory().Write(uint32(namePtr), []byte(name)) {
		log.Errorf("Memory.Write(%d, %d) out of range of memory size %d",
			namePtr, nameSize, c.wasmModule.Memory().Size())
	}

	//TODO better implement this
	_, err = c.funcs.check.Call(c.ctx, namePtr, nameSize)
	if err != nil {
		log.Errorf("failed to invoke \"add\": %v", err)
	}

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

	// Generate check ID
	c.id = checkid.BuildID(c.String(), integrationConfigDigest, data, initConfig)

	// TODO implement here interface between wasm and checks (return and parameters)

	// commonGlobalOptions := integration.CommonGlobalConfig{}
	// if err := yaml.Unmarshal(initConfig, &commonGlobalOptions); err != nil {
	// 	log.Errorf("invalid init_config section for check %s: %s", string(c.id), err)
	// 	return err
	// }

	// // Set service for this check
	// if len(commonGlobalOptions.Service) > 0 {
	// 	s, err := c.senderManager.GetSender(c.id)
	// 	if err != nil {
	// 		log.Errorf("failed to retrieve a sender for check %s: %s", string(c.id), err)
	// 	} else {
	// 		s.SetCheckService(commonGlobalOptions.Service)
	// 	}
	// }

	// commonOptions := integration.CommonInstanceConfig{}
	// if err := yaml.Unmarshal(data, &commonOptions); err != nil {
	// 	log.Errorf("invalid instance section for check %s: %s", string(c.id), err)
	// 	return err
	// }

	// // See if a collection interval was specified
	// if commonOptions.MinCollectionInterval > 0 {
	// 	c.interval = time.Duration(commonOptions.MinCollectionInterval) * time.Second
	// }

	// // Disable default hostname if specified
	// if commonOptions.EmptyDefaultHostname {
	// 	s, err := c.senderManager.GetSender(c.id)
	// 	if err != nil {
	// 		log.Errorf("failed to retrieve a sender for check %s: %s", string(c.id), err)
	// 	} else {
	// 		s.DisableDefaultHostname(true)
	// 	}
	// }

	// // Set configured service for this check, overriding the one possibly defined globally
	// if len(commonOptions.Service) > 0 {
	// 	s, err := c.senderManager.GetSender(c.id)
	// 	if err != nil {
	// 		log.Errorf("failed to retrieve a sender for check %s: %s", string(c.id), err)
	// 	} else {
	// 		s.SetCheckService(commonOptions.Service)
	// 	}
	// }

	// cInitConfig := TrackedCString(string(initConfig))
	// cInstance := TrackedCString(string(data))
	// cCheckID := TrackedCString(string(c.id))
	// cCheckName := TrackedCString(c.ModuleName)
	// defer C._free(unsafe.Pointer(cInitConfig))
	// defer C._free(unsafe.Pointer(cInstance))
	// defer C._free(unsafe.Pointer(cCheckID))
	// defer C._free(unsafe.Pointer(cCheckName))

	// var check *C.rtloader_pyobject_t
	// res := C.get_check(rtloader, c.class, cInitConfig, cInstance, cCheckID, cCheckName, &check)
	// var rtLoaderError error
	// if res == 0 {
	// 	rtLoaderError = getRtLoaderError()
	// 	if rtLoaderError != nil && strings.Contains(rtLoaderError.Error(), skipInstanceErrorPattern) {
	// 		return fmt.Errorf("%w: %w", checkbase.ErrSkipCheckInstance, rtLoaderError)
	// 	}

	// 	log.Warnf("could not get a '%s' check instance with the new api: %s", c.ModuleName, rtLoaderError)
	// 	log.Warn("trying to instantiate the check with the old api, passing agentConfig to the constructor")

	// 	allSettings := config.Datadog.AllSettings()
	// 	agentConfig, err := yaml.Marshal(allSettings)
	// 	if err != nil {
	// 		log.Errorf("error serializing agent config: %s", err)
	// 		return err
	// 	}
	// 	cAgentConfig := TrackedCString(string(agentConfig))
	// 	defer C._free(unsafe.Pointer(cAgentConfig))

	// 	res := C.get_check_deprecated(rtloader, c.class, cInitConfig, cInstance, cAgentConfig, cCheckID, cCheckName, &check)
	// 	if res == 0 {
	// 		rtLoaderDeprecatedCheckError := getRtLoaderError()
	// 		if strings.Contains(rtLoaderDeprecatedCheckError.Error(), skipInstanceErrorPattern) {
	// 			return fmt.Errorf("%w: %w", checkbase.ErrSkipCheckInstance, rtLoaderDeprecatedCheckError)
	// 		}
	// 		if rtLoaderError != nil {
	// 			return fmt.Errorf("could not invoke '%s' wasm check constructor. New constructor API returned:\n%wDeprecated constructor API returned:\n%w", c.ModuleName, rtLoaderError, rtLoaderDeprecatedCheckError)
	// 		}
	// 		return fmt.Errorf("could not invoke '%s' wasm check constructor: %w", c.ModuleName, rtLoaderDeprecatedCheckError)
	// 	}
	// 	log.Warnf("passing `agentConfig` to the constructor is deprecated, please use the `get_config` function from the 'datadog_agent' package (%s).", c.ModuleName)
	// }
	// c.instance = check
	// c.source = source

	// // Add the possibly configured service as a tag for this check
	// s, err := c.senderManager.GetSender(c.id)
	// if err != nil {
	// 	log.Errorf("failed to retrieve a sender for check %s: %s", string(c.id), err)
	// } else {
	// 	s.FinalizeCheckServiceTag()
	// 	s.SetNoIndex(commonOptions.NoIndex)
	// }

	// c.initConfig = string(initConfig)
	// c.instanceConfig = string(data)

	// log.Debugf("wasm check configure done %s", c.ModuleName)
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
