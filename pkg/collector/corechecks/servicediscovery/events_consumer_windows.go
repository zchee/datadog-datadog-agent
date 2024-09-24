// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package servicediscovery

import (
	sdconfig "github.com/DataDog/datadog-agent/pkg/collector/corechecks/servicediscovery/config"
	eventmodel "github.com/DataDog/datadog-agent/pkg/process/events/model"
	"github.com/DataDog/datadog-agent/pkg/security/secl/model"
	smodel "github.com/DataDog/datadog-agent/pkg/security/secl/model"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

// ProcessConsumer is part of the event monitoring module of the system-probe. It receives
// events, batches them in the messages channel and serves the messages to the process-agent
// over GRPC when requested
type ProcessEventConsumer struct {
}

const (
	processEventChanSize = 100
)

var (
	// allowedEventTypes defines allowed event type for consumers
	allowedEventTypes = []model.EventType{model.ForkEventType, model.ExecEventType, model.ExitEventType}
)

// NewProcessConsumer returns a new ProcessConsumer instance
func NewProcessEventConsumer(_ *sdconfig.Config) (*ProcessEventConsumer, error) {
	return &ProcessEventConsumer{}, nil
}

//nolint:revive // TODO(PROC) Fix revive linter
func (p *ProcessEventConsumer) Start() error {
	return nil
}

//nolint:revive // TODO(PROC) Fix revive linter
func (p *ProcessEventConsumer) Stop() {
}

// ID returns id for process monitor
func (p *ProcessEventConsumer) ID() string {
	return "service_discovery"
}

// Copy should copy the given event or return nil to discard it
func (p *ProcessEventConsumer) Copy(event *model.Event) any {
	var result eventmodel.ProcessEvent

	valueEMEventType := uint32(event.GetEventType())
	result.EMEventType = valueEMEventType

	valueCollectionTime := event.GetTimestamp()
	result.CollectionTime = valueCollectionTime

	valueContainerID := event.GetContainerId()
	result.ContainerID = valueContainerID

	valuePpid := event.GetProcessPpid()
	result.Ppid = valuePpid

	if event.GetEventType() == smodel.ExecEventType {
		valueExecTime := event.GetProcessExecTime()
		result.ExecTime = valueExecTime
	}

	if event.GetEventType() == smodel.ExitEventType {
		valueExitTime := event.GetProcessExitTime()
		result.ExitTime = valueExitTime
	}

	if event.GetEventType() == smodel.ExitEventType {
		valueExitCode := event.GetExitCode()
		result.ExitCode = valueExitCode
	}
	return &result
}

// ChanSize returns the chan size used by this consumer
func (p *ProcessEventConsumer) ChanSize() int {
	return processEventChanSize
}

// ID returns id for process monitor
func (p *ProcessEventConsumer) HandleEvent(event any) {
	e, ok := event.(*eventmodel.ProcessEvent)
	if !ok {
		log.Errorf("Event is not a Process Lifecycle Event")
		return
	}

	// transcode event type
	switch e.EMEventType {
	case uint32(smodel.ExecEventType):
		e.EventType = eventmodel.Exec
	case uint32(smodel.ExitEventType):
		e.EventType = eventmodel.Exit
	case uint32(smodel.ForkEventType):
		e.EventType = eventmodel.Fork
	default:
		log.Errorf("Event is not a Process Lifecycle Event")
		return
	}
}

// EventTypes returns the event types handled by this consumer
func (p *ProcessEventConsumer) EventTypes() []smodel.EventType {
	return []smodel.EventType{
		smodel.ForkEventType,
		smodel.ExecEventType,
		smodel.ExitEventType,
	}
}
