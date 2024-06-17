// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2022-present Datadog, Inc.

package flowaggregator

import (
	"sync"
	"time"

	"github.com/DataDog/datadog-agent/comp/core/log"
	"github.com/DataDog/datadog-agent/comp/netflow/common"
	"github.com/DataDog/datadog-agent/comp/netflow/portrollup"
	"github.com/DataDog/datadog-agent/comp/rdnsquerier"
	"go.uber.org/atomic"
)

var timeNow = time.Now

// flowContext contains flow information and additional flush related data
type flowContext struct {
	flow                *common.Flow
	nextFlush           time.Time
	lastSuccessfulFlush time.Time
}

// flowAccumulator is used to accumulate aggregated flows
type flowAccumulator struct {
	flows map[uint64]flowContext
	// mutex is needed to protect `flows` since `flowAccumulator.add()` and  `flowAccumulator.flush()`
	// are called by different routines.
	flowsMutex sync.Mutex

	flowFlushInterval time.Duration
	flowContextTTL    time.Duration

	portRollup          *portrollup.EndpointPairPortRollupStore
	portRollupThreshold int
	portRollupDisabled  bool

	hashCollisionFlowCount *atomic.Uint64

	logger log.Component

	rdnsQuerier rdnsquerier.Component
}

func newFlowContext(flow *common.Flow) flowContext {
	now := timeNow()
	return flowContext{
		flow:      flow,
		nextFlush: now,
	}
}

func newFlowAccumulator(aggregatorFlushInterval time.Duration, aggregatorFlowContextTTL time.Duration, portRollupThreshold int, portRollupDisabled bool, logger log.Component, rdnsQuerier rdnsquerier.Component) *flowAccumulator { // JMWINIT2
	return &flowAccumulator{
		flows:                  make(map[uint64]flowContext),
		flowFlushInterval:      aggregatorFlushInterval,
		flowContextTTL:         aggregatorFlowContextTTL,
		portRollup:             portrollup.NewEndpointPairPortRollupStore(portRollupThreshold),
		portRollupThreshold:    portRollupThreshold,
		portRollupDisabled:     portRollupDisabled,
		hashCollisionFlowCount: atomic.NewUint64(0),
		logger:                 logger,
		rdnsQuerier:            rdnsQuerier,
	}
}

// flush will flush specific flow context (distinct hash) if nextFlush is reached
// once a flow context is flushed nextFlush will be updated to the next flush time
//
// flowContextTTL:
// flowContextTTL defines the duration we should keep a specific flowContext in `flowAccumulator.flows`
// after `lastSuccessfulFlush`. // Flow context in `flowAccumulator.flows` map will be deleted if `flowContextTTL`
// is reached to avoid keeping flow context that are not seen anymore.
// We need to keep flowContext (contains `nextFlush` and `lastSuccessfulFlush`) after flush
// to be able to flush at regular interval (`flowFlushInterval`).
// Example, after a flush, flowContext will have a new nextFlush, that will be the next flush time for new flows being added.
func (f *flowAccumulator) flush() []*common.Flow { // JMW5
	f.flowsMutex.Lock()
	defer f.flowsMutex.Unlock()

	var flowsToFlush []*common.Flow
	for key, flowCtx := range f.flows {
		now := timeNow()
		if flowCtx.flow == nil && (flowCtx.lastSuccessfulFlush.Add(f.flowContextTTL).Before(now)) {
			f.logger.Tracef("Delete flow context (key=%d, lastSuccessfulFlush=%s, nextFlush=%s)", key, flowCtx.lastSuccessfulFlush.String(), flowCtx.nextFlush.String())
			// delete flowCtx wrapper if there is no successful flushes since `flowContextTTL`
			delete(f.flows, key)
			continue
		}
		if flowCtx.nextFlush.After(now) {
			continue
		}
		if flowCtx.flow != nil {
			// JMWJMW do the actual enrichment here, if cache has resolved the IP addresses to hostnames
			// JMW limit - cache TTL must be >= flow aggregation interval - what is the config for that???  What if a customer wants 1 minute TTL for cache and there is a 5 minute aggregation interval?
			// JMWFRI enrichWithReverseDNS(flowCtx.flow)
			flowsToFlush = append(flowsToFlush, flowCtx.flow)
			flowCtx.lastSuccessfulFlush = now
			flowCtx.flow = nil
		}
		flowCtx.nextFlush = flowCtx.nextFlush.Add(f.flowFlushInterval)
		f.flows[key] = flowCtx
	}
	return flowsToFlush
}

/* JMWFRI should we enrich common.Flow or payload.FlowPayload?
func enrichWithReverseDNS(flow *common.Flow) {
	// JMWADD resolveHostnames()
	flow.SrcRdnsHostname = f.rDNSCache.TryGet(flow.SrcAddr)
	flow.DstRdnsDomain = f.rDNSCache.TryGet(flow.DstAddr)
}
*/

// JMWADD rDNSCache to flowAccumulator
// JMWADD resolveHostnames()
// func (f *flowAccumulator) resolveHostnames(flow *common.Flow) {
//	flow.SrcRdnsDomain = f.rDNSCache.Get(flow.SrcAddr)
//	flow.DstRdnsDomain = f.rDNSCache.Get(flow.DstAddr)
//}

func (f *flowAccumulator) add(flowToAdd *common.Flow) { // JMW1
	//f.logger.Debugf("JMW Add new flow: %+v", flowToAdd)
	f.logger.Tracef("Add new flow: %+v", flowToAdd)

	if !f.portRollupDisabled {
		// Handle port rollup
		f.portRollup.Add(flowToAdd.SrcAddr, flowToAdd.DstAddr, uint16(flowToAdd.SrcPort), uint16(flowToAdd.DstPort))
		ephemeralStatus := f.portRollup.IsEphemeral(flowToAdd.SrcAddr, flowToAdd.DstAddr, uint16(flowToAdd.SrcPort), uint16(flowToAdd.DstPort))
		switch ephemeralStatus {
		case portrollup.IsEphemeralSourcePort:
			flowToAdd.SrcPort = portrollup.EphemeralPort
		case portrollup.IsEphemeralDestPort:
			flowToAdd.DstPort = portrollup.EphemeralPort
		}
	}

	// JMW - Enabled or Disabled, like portRollupDisabled?
	// JMW should flowAccumulator resolve hostnames or should it be done before calling add()?  I think goflow sends it to the channel, received in FlowAggregator::run(), and then add() is called.
	// if !f.rDNSDisabled {
	// 	// Tell the rDNSCache that we are interested in the source and destination IP addresses
	// JMWFRI move to FlowAggregator?
	// JMWFRI f.rDNSCache.PreFetch(SrcAddr)
	// JMWFRI f.rDNSCache.PreFetch(DstAddr)
	// }

	f.flowsMutex.Lock()
	defer f.flowsMutex.Unlock()

	aggHash := flowToAdd.AggregationHash()
	aggFlow, ok := f.flows[aggHash]
	if !ok {
		f.flows[aggHash] = newFlowContext(flowToAdd) // JMW2
		// JMWFRI - can/should we do this here?  (w/ defer so it's done after the lock is released)
		// JMWJMW but aren't defers done in reverse order?  so the lock would still be held when this is called?  Instead, can I defer a function that uses variables that aren't set until here?  OR pass callback func that can be called after the lock is released, and it will acquire the lock again?  OR if IP is in cache already then set the hostname here while we have the lock
		// JMWFRI defer rdnscache.PreFetch(flowToAdd.SrcAddr, flowToAdd.DstAddr)

		// JMWJMW how long can the flow exist?  does it last after a flush (and get resused??)  if so do we need to always go thru the cache to see if the hostname was updated? - see JMWRDNS2, below
		// JMWRDNS1 for the first prototype simply get the hostname synchronously here - add code timing?
		flowToAdd.SrcReverseDNSHostname = f.rdnsQuerier.GetHostname(flowToAdd.SrcAddr)
		flowToAdd.DstReverseDNSHostname = f.rdnsQuerier.GetHostname(flowToAdd.DstAddr)
		// JMWRDNS1 rdnsCache.Get(flowToAdd.SrcAddr, callbackFuncToSetTheHostname)

		// JMWTEST how to fix TestAggregator failure
		return
	}
	if aggFlow.flow == nil {
		// JMWRDNS2 this path is for when a flow has been flushed and a new flow comes in for the same hash - we need to do the rdns enrichment here too
		aggFlow.flow = flowToAdd
		// JMWRDNS2 for the first prototype simply get the hostname synchronously here - add code timing?
		flowToAdd.SrcReverseDNSHostname = f.rdnsQuerier.GetHostname(flowToAdd.SrcAddr)
		flowToAdd.DstReverseDNSHostname = f.rdnsQuerier.GetHostname(flowToAdd.DstAddr)
		// JMWRDNS2 rdnsCache.Get(flowToAdd.SrcAddr, callbackFuncToSetTheHostname)
	} else {
		// use go routine for hash collision detection to avoid blocking critical path
		go f.detectHashCollision(aggHash, *aggFlow.flow, *flowToAdd)

		// accumulate flowToAdd with existing flow(s) with same hash
		aggFlow.flow.Bytes += flowToAdd.Bytes
		aggFlow.flow.Packets += flowToAdd.Packets
		// JMW add metrics here to count if/when aggregation of overlapping timeslots occur
		aggFlow.flow.StartTimestamp = common.Min(aggFlow.flow.StartTimestamp, flowToAdd.StartTimestamp)
		aggFlow.flow.EndTimestamp = common.Max(aggFlow.flow.EndTimestamp, flowToAdd.EndTimestamp)
		aggFlow.flow.SequenceNum = common.Max(aggFlow.flow.SequenceNum, flowToAdd.SequenceNum)
		aggFlow.flow.TCPFlags |= flowToAdd.TCPFlags

		// keep first non-null value for custom fields
		if flowToAdd.AdditionalFields != nil {
			if aggFlow.flow.AdditionalFields == nil {
				aggFlow.flow.AdditionalFields = make(common.AdditionalFields)
			}

			for field, value := range flowToAdd.AdditionalFields {
				if _, ok := aggFlow.flow.AdditionalFields[field]; !ok {
					aggFlow.flow.AdditionalFields[field] = value
				}
			}
		}
	}
	f.flows[aggHash] = aggFlow
}

func (f *flowAccumulator) getFlowContextCount() int {
	f.flowsMutex.Lock()
	defer f.flowsMutex.Unlock()

	return len(f.flows)
}

func (f *flowAccumulator) detectHashCollision(hash uint64, existingFlow common.Flow, flowToAdd common.Flow) {
	if !common.IsEqualFlowContext(existingFlow, flowToAdd) {
		f.logger.Warnf("Hash collision for flows with hash `%d`: existingFlow=`%+v` flowToAdd=`%+v`", hash, existingFlow, flowToAdd)
		f.hashCollisionFlowCount.Inc() // JMW this becomes metric: datadog.netflow.aggregator.hash_collisions
	}
}
