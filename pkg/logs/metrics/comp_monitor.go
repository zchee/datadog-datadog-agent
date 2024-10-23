// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//nolint:revive // TODO(AML) Fix revive linter
package metrics

import (
	"sync"
	"time"

	"github.com/DataDog/datadog-agent/pkg/telemetry"
)

type Size interface {
	Size() int64
}

// var TlmIngressBytes = telemetry.NewCounter("logs_component", "ingress_bytes", []string{"name", "instance"}, "")
// var TlmEgressBytes = telemetry.NewCounter("logs_component", "egress_bytes", []string{"name", "instance"}, "")
var TlmUtilization = telemetry.NewGauge("logs_component", "utilization", []string{"name", "instance"}, "")
var TlmCapacity = telemetry.NewGauge("logs_component", "capacity", []string{"name", "instance"}, "")

type IngressMonitor struct {
	sync.Mutex
	ingress  int64
	egress   int64
	avg      float64
	samples  float64
	name     string
	instance string
	ticker   *time.Ticker
}

func (i *IngressMonitor) AddIngress(size int64) {
	i.Lock()
	defer i.Unlock()
	i.ingress += size
	i.sample()
	i.reportIfNeeded()
}

func (i *IngressMonitor) AddEgress(size int64) {
	i.Lock()
	defer i.Unlock()
	i.egress += size
	i.sample()
	i.reportIfNeeded()
}

func (i *IngressMonitor) sample() {
	i.samples++
	new := float64(i.ingress - i.egress)
	i.avg = (i.avg*(i.samples-1) + new) / i.samples
}
func (i *IngressMonitor) reportIfNeeded() {
	select {
	case <-i.ticker.C:
		TlmCapacity.Set(float64(i.avg), i.name, i.instance)
		i.avg = 0
		i.samples = 0
	default:
	}
}

var Monitors = make(map[string]*IngressMonitor)
var MonitorsLock = sync.RWMutex{}

func getMonitor(name string, instance string) *IngressMonitor {
	MonitorsLock.RLock()
	if Monitors[name+instance] == nil {
		MonitorsLock.RUnlock()
		MonitorsLock.Lock()
		Monitors[name+instance] = &IngressMonitor{name: name, instance: instance, ticker: time.NewTicker(5 * time.Second)}
		MonitorsLock.Unlock()
	} else {
		defer MonitorsLock.RUnlock()
	}
	return Monitors[name+instance]
}

func ReportComponentIngress(size Size, name string, instance string) {
	m := getMonitor(name, instance)
	m.AddIngress(size.Size())
}

func ReportComponentEgress(size Size, name string, instance string) {
	m := getMonitor(name, instance)
	m.AddEgress(size.Size())
}

type UtilizationMonitor struct {
	inUse      float64
	idle       float64
	startIdle  time.Time
	startInUse time.Time
	name       string
	instance   string
	ticker     *time.Ticker
}

func NewUtilizationMonitor(name, instance string) *UtilizationMonitor {
	return &UtilizationMonitor{
		startIdle:  time.Now(),
		startInUse: time.Now(),
		name:       name,
		instance:   instance,
		ticker:     time.NewTicker(5 * time.Second),
	}
}

func (u *UtilizationMonitor) Start() {
	u.idle += float64(time.Since(u.startIdle) / time.Millisecond)
	u.startInUse = time.Now()
}

func (u *UtilizationMonitor) Stop() {
	u.inUse += float64(time.Since(u.startInUse) / time.Millisecond)
	u.startIdle = time.Now()
	select {
	case <-u.ticker.C:
		TlmUtilization.Set(u.inUse/(u.idle+u.inUse), u.name, u.instance)
		u.idle = 0
		u.inUse = 0
	default:
	}

}
