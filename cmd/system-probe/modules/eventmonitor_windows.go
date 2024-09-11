// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build windows

package modules

import (
	"github.com/DataDog/datadog-agent/cmd/system-probe/api/module"
	"github.com/DataDog/datadog-agent/cmd/system-probe/config"
	sd "github.com/DataDog/datadog-agent/pkg/collector/corechecks/servicediscovery"
	sdconfig "github.com/DataDog/datadog-agent/pkg/collector/corechecks/servicediscovery/config"
	"github.com/DataDog/datadog-agent/pkg/eventmonitor"
	netconfig "github.com/DataDog/datadog-agent/pkg/network/config"
)

// EventMonitor - Event monitor Factory
var EventMonitor = module.Factory{
	Name:             config.EventMonitorModule,
	ConfigNamespaces: eventMonitorModuleConfigNamespaces,
	Fn:               createEventMonitorModule,
}

func createProcessMonitorConsumer(_ *eventmonitor.EventMonitor, _ *netconfig.Config) (eventmonitor.EventConsumerInterface, error) {
	return nil, nil
}

func createServiceDiscoveryProcessConsumer(em *eventmonitor.EventMonitor) (eventmonitor.EventConsumerInterface, error) {
	sdconfig := sdconfig.NewConfig()
	consumer, err := sd.NewProcessEventConsumer(sdconfig)
	if err != nil {
		return nil, err
	}

	err = em.AddEventConsumer(consumer)
	if err != nil {
		return nil, err
	}

	return consumer, nil
}
