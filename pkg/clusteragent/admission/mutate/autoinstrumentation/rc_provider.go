// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build kubeapiserver

package autoinstrumentation

import (
	"encoding/json"
	"errors"
	"sort"
	"time"

	"github.com/DataDog/datadog-agent/pkg/clusteragent/admission/metrics"
	"github.com/DataDog/datadog-agent/pkg/clusteragent/telemetry"
	rcclient "github.com/DataDog/datadog-agent/pkg/config/remote/client"
	"github.com/DataDog/datadog-agent/pkg/remoteconfig/state"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

// remoteConfigProvider consumes tracing configs from RC and delivers them to the patcher
type remoteConfigProvider struct {
	client                  *rcclient.Client
	pollInterval            time.Duration
	clusterName             string
	lastProcessedRCRevision int64
	rcConfigIDs             map[string]struct{}

	cache              *instrumentationConfigurationCache
	telemetryCollector telemetry.TelemetryCollector
}

type rcConfigs struct {
	path    string
	request Request
}

type rcProvider interface {
	start(stopCh <-chan struct{})
}

var _ rcProvider = &remoteConfigProvider{}

func newRemoteConfigProvider(
	client *rcclient.Client,
	clusterName string,
	cache *instrumentationConfigurationCache,
	telemetryCollector telemetry.TelemetryCollector,
) (*remoteConfigProvider, error) {
	if client == nil {
		return nil, errors.New("remote config client not initialized")
	}
	return &remoteConfigProvider{
		client:                  client,
		clusterName:             clusterName,
		pollInterval:            10 * time.Second,
		lastProcessedRCRevision: 0,
		rcConfigIDs:             make(map[string]struct{}),
		cache:                   cache,
		telemetryCollector:      telemetryCollector,
	}, nil
}

func (rcp *remoteConfigProvider) start(stopCh <-chan struct{}) {
	log.Info("Remote Enablement: starting remote-config provider")
	rcp.client.Subscribe(state.ProductAPMTracing, rcp.process)
	rcp.client.Start()
	defer rcp.client.Close()

	for {
		select {
		case <-stopCh:
			log.Info("Remote Enablement: shutting down remote-config patch provider")
			return
		}
	}
}

// process is the event handler called by the RC client on config updates
func (rcp *remoteConfigProvider) process(update map[string]state.RawConfig, applyStateCallback func(string, state.ApplyStatus)) {
	log.Infof("Got %d updates from remote-config", len(update))
	var invalid float64
	toDelete := make(map[string]struct{}, len(rcp.rcConfigIDs))
	for k := range rcp.rcConfigIDs {
		toDelete[k] = struct{}{}
	}

	// order all configs received from RC
	orderedConfigs := []int64{}
	allConfigs := map[int64]rcConfigs{}
	for path, config := range update {
		var req Request
		err := json.Unmarshal(config.Config, &req)
		if err != nil {
			invalid++
			rcp.telemetryCollector.SendRemoteConfigMutateEvent(req.getApmRemoteConfigEvent(err, telemetry.ConfigParseFailure))
			log.Errorf("Error while parsing config: %v", err)
			continue
		}
		req.RcVersion = config.Metadata.Version
		orderedConfigs = append(orderedConfigs, req.Revision)
		allConfigs[req.Revision] = rcConfigs{
			path:    path,
			request: req,
		}
	}
	sort.SliceStable(orderedConfigs, func(i, j int) bool { return orderedConfigs[i] < orderedConfigs[j] })

	for _, revision := range orderedConfigs {
		rcConfig, ok := allConfigs[revision]
		if !ok {
			log.Errorf("RC config not found")
		}
		req := rcConfig.request
		if _, ok := toDelete[req.ID]; ok {
			delete(toDelete, req.ID)
		} else {
			rcp.rcConfigIDs[req.ID] = struct{}{}
		}

		if shouldSkipConfig(req, rcp.lastProcessedRCRevision, rcp.clusterName) {
			continue
		}

		log.Infof("Remote Enablement: updating with config %+v", req)
		metrics.PatchAttempts.Inc()
		resp := rcp.cache.update(req)
		var err error
		if resp.Status.State == state.ApplyStateError {
			metrics.PatchErrors.Inc()
			rcp.telemetryCollector.SendRemoteConfigMutateEvent(req.getApmRemoteConfigEvent(err, telemetry.FailedToMutateConfig))
		} else if resp.Status.State == state.ApplyStateAcknowledged {
			metrics.PatchCompleted.Inc()
			rcp.telemetryCollector.SendRemoteConfigMutateEvent(req.getApmRemoteConfigEvent(err, telemetry.Success))
		}
		applyStateCallback(rcConfig.path, resp.Status)
		rcp.lastProcessedRCRevision = req.Revision
	}

	for configToDelete := range toDelete {
		log.Infof("Remote Enablement: deleting config %s", configToDelete)
		metrics.DeleteRemoteConfigsAttempts.Inc()
		if err := rcp.cache.delete(configToDelete); err != nil {
			log.Errorf("Remote Enablement: failed to delete config %s with %v", configToDelete, err)
			metrics.DeleteRemoteConfigsErrors.Inc()
		} else {
			metrics.DeleteRemoteConfigsCompleted.Inc()
			delete(rcp.rcConfigIDs, configToDelete)
		}

	}

	metrics.InvalidRemoteConfigs.Set(invalid)
}

func shouldSkipConfig(req Request, lastAppliedRevision int64, clusterName string) bool {
	// check if config should be applied based on presence K8sTargetV2 object
	if req.K8sTargetV2 == nil || len(req.K8sTargetV2.ClusterTargets) == 0 {
		log.Debugf("Remote Enablement: skipping config %s because K8sTargetV2 is not set", req.ID)
		return true
	}

	// check if config should be applied based on RC revision
	lastAppliedTime := time.UnixMilli(lastAppliedRevision)
	requestTime := time.UnixMilli(req.Revision)

	if requestTime.Before(lastAppliedTime) || requestTime.Equal(lastAppliedTime) {
		log.Debugf("Remote Enablement: skipping config %s because it has already been applied: revision %v, last applied revision %v", req.ID, requestTime, lastAppliedTime)
		return true
	}

	isTargetingCluster := false
	for _, target := range req.K8sTargetV2.ClusterTargets {
		if target.ClusterName == clusterName {
			isTargetingCluster = true
			break
		}
	}
	if !isTargetingCluster {
		log.Debugf("Remote Enablement: skipping config %s because it's not targeting current cluster %s", req.ID, req.K8sTargetV2.ClusterTargets[0].ClusterName)
	}
	return !isTargetingCluster

}
