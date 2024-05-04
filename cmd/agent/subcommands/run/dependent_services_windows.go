// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.
//go:build windows

package run

import (

	"github.com/DataDog/datadog-agent/pkg/config"
	"github.com/DataDog/datadog-agent/pkg/util/log"
	"github.com/DataDog/datadog-agent/pkg/util/winutil"
)

type serviceInitFunc func() (err error)

// Servicedef defines a service
type Servicedef struct {
	name       string
	configKeys map[string]config.Config

	serviceName string
	serviceInit serviceInitFunc
}

var subservices = []Servicedef{
	{
		name: "apm",
		configKeys: map[string]config.Config{
			"apm_config.enabled": config.Datadog,
		},
		serviceName: "datadog-trace-agent",
		serviceInit: apmInit,
	},
	{
		name: "process",
		configKeys: map[string]config.Config{
			"process_config.enabled":                      config.Datadog,
			"process_config.process_collection.enabled":   config.Datadog,
			"process_config.container_collection.enabled": config.Datadog,
			"process_config.process_discovery.enabled":    config.Datadog,
			"network_config.enabled":                      config.SystemProbe,
			"system_probe_config.enabled":                 config.SystemProbe,
		},
		serviceName: "datadog-process-agent",
		serviceInit: processInit,
	},
	{
		name: "sysprobe",
		configKeys: map[string]config.Config{
			"network_config.enabled":          config.SystemProbe,
			"system_probe_config.enabled":     config.SystemProbe,
			"windows_crash_detection.enabled": config.SystemProbe,
			"runtime_security_config.enabled": config.SystemProbe,
		},
		serviceName: "datadog-system-probe",
		serviceInit: sysprobeInit,
	},
	{
		name: "cws",
		configKeys: map[string]config.Config{
			"runtime_security_config.enabled": config.SystemProbe,
		},
		serviceName: "datadog-security-agent",
		serviceInit: securityInit,
	},
}

func apmInit() error {
	return nil
}

func processInit() error {
	return nil
}

func sysprobeInit() error {
	return nil
}

func securityInit() error {
	return nil
}

// Enable enables the service in the service control manager
func (s *Servicedef) Enable() error {
	return winutil.EnableService(s.serviceName)
}

// Disable disables the service in the service control manager
func (s *Servicedef) Disable() error {
	return winutil.DisableService(s.serviceName)
}

// Start starts the service
func (s *Servicedef) Start() error {
	if s.serviceInit != nil {
		err := s.serviceInit()
		if err != nil {
			log.Warnf("Failed to initialize %s service: %s", s.name, err.Error())
			return err
		}
	}
	return winutil.StartService(s.serviceName, "is", "manual-started")
}

// Stop stops the service
func (s *Servicedef) Stop() error {
	return nil
}
