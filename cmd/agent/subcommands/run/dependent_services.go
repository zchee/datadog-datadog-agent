// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package run

import (
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

// start various subservices (apm, logs, process, system-probe) based on the config file settings

// IsEnabled checks to see if a given service should be started
func (s *Servicedef) IsEnabled() bool {
	for configKey, cfg := range s.configKeys {
		if cfg.GetBool(configKey) {
			return true
		}
	}
	return false
}

func startDependentServices() {
	for _, svc := range subservices {
		if svc.IsEnabled() {
			log.Debugf("Enabling service: %s", svc.name)
			err := svc.Enable()
			if err != nil {
				log.Warnf("Failed to enable service %s: %s", svc.name, err.Error())
			}
			log.Debugf("Attempting to start service: %s", svc.name)
			err = svc.Start()
			if err != nil {
				log.Warnf("Failed to start services %s: %s", svc.name, err.Error())
			} else {
				log.Debugf("Started service %s", svc.name)
			}
		} else {
			log.Infof("Service %s is disabled, not starting", svc.name)
			// disable it in SCM just to be sure
			err := svc.Disable()
			if err != nil {
				log.Warnf("Failed to disable service in SCM %s: %s", svc.name, err.Error())
			}
		}
	}
}

func stopDependentServices() {
	for _, svc := range subservices {
		// disable each service so that it can't be restarted from underneath us
		err := svc.Disable()
		if err != nil {
			log.Warnf("Failed to disable service %s: %s", svc.name, err.Error())
		}
	}
	// do same loop, once they're all disabled, stop them
	for _, svc := range subservices {
		err := svc.Stop()
		if err != nil {
			log.Warnf("Failed to stop service %s: %s", svc.name, err.Error())
		}
	}
}
