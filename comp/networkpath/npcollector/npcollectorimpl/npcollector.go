// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

// Package npcollectorimpl implements network path collector
package npcollectorimpl

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	model "github.com/DataDog/agent-payload/v5/process"
	ddgostatsd "github.com/DataDog/datadog-go/v5/statsd"
	"go.uber.org/atomic"

	log "github.com/DataDog/datadog-agent/comp/core/log/def"
	telemetryComp "github.com/DataDog/datadog-agent/comp/core/telemetry"
	"github.com/DataDog/datadog-agent/comp/forwarder/eventplatform"
	"github.com/DataDog/datadog-agent/comp/networkpath/npcollector/npcollectorimpl/common"
	"github.com/DataDog/datadog-agent/comp/networkpath/npcollector/npcollectorimpl/pathteststore"
	rdnsquerier "github.com/DataDog/datadog-agent/comp/rdnsquerier/def"
	"github.com/DataDog/datadog-agent/pkg/logs/message"
	"github.com/DataDog/datadog-agent/pkg/networkpath/metricsender"
	"github.com/DataDog/datadog-agent/pkg/networkpath/payload"
	"github.com/DataDog/datadog-agent/pkg/networkpath/telemetry"
	"github.com/DataDog/datadog-agent/pkg/networkpath/traceroute"
	"github.com/DataDog/datadog-agent/pkg/process/statsd"
)

type npCollectorImpl struct {
	collectorConfigs *collectorConfigs

	// Deps
	epForwarder  eventplatform.Forwarder
	logger       log.Component
	metricSender metricsender.MetricSender
	statsdClient ddgostatsd.ClientInterface
	rdnsquerier  rdnsquerier.Component

	// Counters
	receivedPathtestCount    *atomic.Uint64
	processedTracerouteCount *atomic.Uint64

	// Pathtest store
	pathtestStore          *pathteststore.Store
	pathtestInputChan      chan *common.Pathtest
	pathtestProcessingChan chan *pathteststore.PathtestContext

	// Scheduling related
	running       bool
	workers       int
	stopChan      chan struct{}
	flushLoopDone chan struct{}
	runDone       chan struct{}
	flushInterval time.Duration

	// Telemetry component
	telemetrycomp telemetryComp.Component

	// structures needed to ease mocking/testing
	TimeNowFn func() time.Time
	// TODO: instead of mocking traceroute via function replacement like this
	//       we should ideally create a fake/mock traceroute instance that can be passed/injected in NpCollector
	runTraceroute func(cfg traceroute.Config, telemetrycomp telemetryComp.Component) (payload.NetworkPath, error)

	networkDevicesNamespace string
}

func newNoopNpCollectorImpl() *npCollectorImpl {
	return &npCollectorImpl{
		collectorConfigs: &collectorConfigs{},
	}
}

func newNpCollectorImpl(epForwarder eventplatform.Forwarder, collectorConfigs *collectorConfigs, logger log.Component, telemetrycomp telemetryComp.Component, rdnsquerier rdnsquerier.Component) *npCollectorImpl {
	logger.Infof("New NpCollector (workers=%d timeout=%d max_ttl=%d input_chan_size=%d processing_chan_size=%d pathtest_contexts_limit=%d pathtest_ttl=%s pathtest_interval=%s flush_interval=%s)",
		collectorConfigs.workers,
		collectorConfigs.timeout,
		collectorConfigs.maxTTL,
		collectorConfigs.pathtestInputChanSize,
		collectorConfigs.pathtestProcessingChanSize,
		collectorConfigs.pathtestContextsLimit,
		collectorConfigs.pathtestTTL,
		collectorConfigs.pathtestInterval,
		collectorConfigs.flushInterval)

	return &npCollectorImpl{
		epForwarder:      epForwarder,
		collectorConfigs: collectorConfigs,
		logger:           logger,
		rdnsquerier:      rdnsquerier,

		pathtestStore:          pathteststore.NewPathtestStore(collectorConfigs.pathtestTTL, collectorConfigs.pathtestInterval, collectorConfigs.pathtestContextsLimit, logger),
		pathtestInputChan:      make(chan *common.Pathtest, collectorConfigs.pathtestInputChanSize),
		pathtestProcessingChan: make(chan *pathteststore.PathtestContext, collectorConfigs.pathtestProcessingChanSize),
		flushInterval:          collectorConfigs.flushInterval,
		workers:                collectorConfigs.workers,

		networkDevicesNamespace: collectorConfigs.networkDevicesNamespace,

		receivedPathtestCount:    atomic.NewUint64(0),
		processedTracerouteCount: atomic.NewUint64(0),
		TimeNowFn:                time.Now,

		telemetrycomp: telemetrycomp,

		stopChan:      make(chan struct{}),
		runDone:       make(chan struct{}),
		flushLoopDone: make(chan struct{}),

		runTraceroute: runTraceroute,
	}
}

func (s *npCollectorImpl) ScheduleConns(conns []*model.Connection) {
	if !s.collectorConfigs.connectionsMonitoringEnabled {
		return
	}
	startTime := s.TimeNowFn()
	for _, conn := range conns {
		remoteAddr := conn.Raddr
		protocol := convertProtocol(conn.GetType())
		var remotePort uint16
		// UDP traces should not be done to the active
		// port
		if protocol != payload.ProtocolUDP {
			remotePort = uint16(conn.Raddr.GetPort())
		}
		if !shouldScheduleNetworkPathForConn(conn) {
			s.logger.Tracef("Skipped connection: addr=%s, port=%d, protocol=%s", remoteAddr, remotePort, protocol)
			continue
		}
		sourceContainer := conn.Laddr.GetContainerId()
		err := s.scheduleOne(remoteAddr.GetIp(), remotePort, protocol, sourceContainer)
		if err != nil {
			s.logger.Errorf("Error scheduling pathtests: %s", err)
		}
	}

	scheduleDuration := s.TimeNowFn().Sub(startTime)
	s.statsdClient.Gauge("datadog.network_path.collector.schedule_duration", scheduleDuration.Seconds(), nil, 1) //nolint:errcheck
}

// scheduleOne schedules pathtests.
// It shouldn't block, if the input channel is full, an error is returned.
func (s *npCollectorImpl) scheduleOne(hostname string, port uint16, protocol payload.Protocol, sourceContainerID string) error {
	if s.pathtestInputChan == nil {
		return errors.New("no input channel, please check that network path is enabled")
	}
	s.logger.Debugf("Schedule traceroute for: hostname=%s port=%d", hostname, port)

	ptest := &common.Pathtest{
		Hostname:          hostname,
		Port:              port,
		Protocol:          protocol,
		SourceContainerID: sourceContainerID,
	}
	select {
	case s.pathtestInputChan <- ptest:
		return nil
	default:
		return fmt.Errorf("collector input channel is full (channel capacity is %d)", cap(s.pathtestInputChan))
	}
}
func (s *npCollectorImpl) start() error {
	if s.running {
		return errors.New("server already started")
	}
	s.running = true

	s.logger.Info("Start NpCollector")

	// Assigning statsd.Client in start() stage since we can't do it in newNpCollectorImpl
	// due to statsd.Client not being configured yet.
	s.metricSender = metricsender.NewMetricSenderStatsd(statsd.Client)
	s.statsdClient = statsd.Client

	go s.listenPathtests()
	go s.flushLoop()
	s.startWorkers()

	return nil
}

func (s *npCollectorImpl) stop() {
	s.logger.Info("Stop NpCollector")
	if !s.running {
		return
	}
	close(s.stopChan)
	<-s.flushLoopDone
	<-s.runDone
	s.running = false
}

func (s *npCollectorImpl) listenPathtests() {
	s.logger.Debug("Starting listening for pathtests")
	for {
		select {
		case <-s.stopChan:
			s.logger.Info("Stopped listening for pathtests")
			s.runDone <- struct{}{}
			return
		case ptest := <-s.pathtestInputChan:
			s.logger.Debugf("Pathtest received: %+v", ptest)
			s.receivedPathtestCount.Inc()
			s.pathtestStore.Add(ptest)
		}
	}
}

func (s *npCollectorImpl) runTracerouteForPath(ptest *pathteststore.PathtestContext) {
	s.logger.Debugf("Run Traceroute for ptest: %+v", ptest)

	startTime := s.TimeNowFn()
	cfg := traceroute.Config{
		DestHostname: ptest.Pathtest.Hostname,
		DestPort:     ptest.Pathtest.Port,
		MaxTTL:       uint8(s.collectorConfigs.maxTTL),
		Timeout:      s.collectorConfigs.timeout,
		Protocol:     ptest.Pathtest.Protocol,
	}

	path, err := s.runTraceroute(cfg, s.telemetrycomp)
	if err != nil {
		s.logger.Errorf("%s", err)
		return
	}
	path.Source.ContainerID = ptest.Pathtest.SourceContainerID
	path.Namespace = s.networkDevicesNamespace
	path.Origin = payload.PathOriginNetworkTraffic

	// Perform reverse DNS lookup on destination and hop IPs
	rdnsHostname, err := s.reverseDNSLookup(path.Destination.IPAddress)
	if err != nil {
		// TODO: should this be an error message?
		s.logger.Errorf("Reverse lookup failed for destination %s: %s", path.Destination.IPAddress, err)
	} else {
		path.Destination.ReverseDNSHostname = rdnsHostname
	}

	for i := range path.Hops {
		// Skip unreachable hops
		if !path.Hops[i].Reachable {
			continue
		}
		rdnsHostname, err := s.reverseDNSLookup(path.Hops[i].IPAddress)
		if err != nil {
			// TODO: should this be an error message?
			s.logger.Errorf("Reverse lookup failed for hop #%d %s: %s", i+1, path.Hops[i].IPAddress, err)
		} else {
			path.Hops[i].Hostname = rdnsHostname
		}
	}

	s.sendTelemetry(path, startTime, ptest)

	payloadBytes, err := json.Marshal(path)
	if err != nil {
		s.logger.Errorf("json marshall error: %s", err)
	} else {
		s.logger.Debugf("network path event: %s", string(payloadBytes))
		m := message.NewMessage(payloadBytes, nil, "", 0)
		err = s.epForwarder.SendEventPlatformEventBlocking(m, eventplatform.EventTypeNetworkPath)
		if err != nil {
			s.logger.Errorf("failed to send event to epForwarder: %s", err)
		}
	}
}

func runTraceroute(cfg traceroute.Config, telemetry telemetryComp.Component) (payload.NetworkPath, error) {
	tr, err := traceroute.New(cfg, telemetry)
	if err != nil {
		return payload.NetworkPath{}, fmt.Errorf("new traceroute error: %s", err)
	}
	path, err := tr.Run(context.TODO())
	if err != nil {
		return payload.NetworkPath{}, fmt.Errorf("run traceroute error: %s", err)
	}
	return path, nil
}

func (s *npCollectorImpl) flushLoop() {
	s.logger.Debugf("Starting flush loop")

	flushTicker := time.NewTicker(s.flushInterval)

	var lastFlushTime time.Time
	for {
		select {
		// stop sequence
		case <-s.stopChan:
			s.logger.Info("Stopped flush loop")
			s.flushLoopDone <- struct{}{}
			flushTicker.Stop()
			return
		// automatic flush sequence
		case flushTime := <-flushTicker.C:
			s.flushWrapper(flushTime, lastFlushTime)
			lastFlushTime = flushTime
		}
	}
}

func (s *npCollectorImpl) flushWrapper(flushTime time.Time, lastFlushTime time.Time) {
	s.logger.Debugf("Flush loop at %s", flushTime)
	if !lastFlushTime.IsZero() {
		flushInterval := flushTime.Sub(lastFlushTime)
		s.statsdClient.Gauge("datadog.network_path.collector.flush_interval", flushInterval.Seconds(), []string{}, 1) //nolint:errcheck
	}

	s.flush()
	s.statsdClient.Gauge("datadog.network_path.collector.flush_duration", s.TimeNowFn().Sub(flushTime).Seconds(), []string{}, 1) //nolint:errcheck
}

func (s *npCollectorImpl) flush() {
	s.statsdClient.Gauge("datadog.network_path.collector.workers", float64(s.workers), []string{}, 1) //nolint:errcheck

	flowsContexts := s.pathtestStore.GetContextsCount()
	s.statsdClient.Gauge("datadog.network_path.collector.pathtest_store_size", float64(flowsContexts), []string{}, 1) //nolint:errcheck

	flushTime := s.TimeNowFn()
	flowsToFlush := s.pathtestStore.Flush()
	s.statsdClient.Gauge("datadog.network_path.collector.pathtest_flushed_count", float64(len(flowsToFlush)), []string{}, 1) //nolint:errcheck

	s.logger.Debugf("Flushing %d flows to the forwarder (flush_duration=%d, flow_contexts_before_flush=%d)", len(flowsToFlush), time.Since(flushTime).Milliseconds(), flowsContexts)

	for _, ptConf := range flowsToFlush {
		s.logger.Tracef("flushed ptConf %s:%d", ptConf.Pathtest.Hostname, ptConf.Pathtest.Port)
		s.pathtestProcessingChan <- ptConf
	}
}

func (s *npCollectorImpl) sendTelemetry(path payload.NetworkPath, startTime time.Time, ptest *pathteststore.PathtestContext) {
	checkInterval := ptest.LastFlushInterval()
	checkDuration := s.TimeNowFn().Sub(startTime)
	telemetry.SubmitNetworkPathTelemetry(
		s.metricSender,
		path,
		checkDuration,
		checkInterval,
		[]string{},
	)
}

func (s *npCollectorImpl) startWorkers() {
	s.logger.Debugf("Starting workers (%d)", s.workers)
	for w := 0; w < s.workers; w++ {
		s.logger.Debugf("Starting worker #%d", w)
		go s.startWorker(w)
	}
}

func (s *npCollectorImpl) startWorker(workerID int) {
	for {
		select {
		case <-s.stopChan:
			s.logger.Debugf("[worker%d] Stopped worker", workerID)
			return
		case pathtestCtx := <-s.pathtestProcessingChan:
			s.logger.Debugf("[worker%d] Handling pathtest hostname=%s, port=%d", workerID, pathtestCtx.Pathtest.Hostname, pathtestCtx.Pathtest.Port)
			s.runTracerouteForPath(pathtestCtx)
			s.processedTracerouteCount.Inc()
		}
	}
}

func (s *npCollectorImpl) reverseDNSLookup(ipString string) (string, error) {
	hostname, err := s.rdnsquerier.GetHostnameSync(ipString)
	if err != nil {
		s.logger.Debugf("Reverse lookup failed for IP %s: %s", ipString, err)
		return "", err
	}
	s.logger.Debugf("Reverse lookup for IP %s: %s", ipString, hostname)
	return hostname, nil
}
