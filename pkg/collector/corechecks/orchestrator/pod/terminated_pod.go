// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.
//go:build kubelet && orchestrator

// Package pod is used for the orchestrator pod check
package pod

import (
	"encoding/json"
	"sync"
	"time"

	v1 "k8s.io/api/core/v1"

	model "github.com/DataDog/agent-payload/v5/process"
	workloadmeta "github.com/DataDog/datadog-agent/comp/core/workloadmeta/def"
	"github.com/DataDog/datadog-agent/pkg/aggregator/sender"
	"github.com/DataDog/datadog-agent/pkg/collector/corechecks/cluster/orchestrator/processors"
	pkgconfigsetup "github.com/DataDog/datadog-agent/pkg/config/setup"
	"github.com/DataDog/datadog-agent/pkg/orchestrator"
	oconfig "github.com/DataDog/datadog-agent/pkg/orchestrator/config"
	"github.com/DataDog/datadog-agent/pkg/util/kubernetes/clustername"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

var startTerminatedPodsCollectionOnce sync.Once

// TerminatedPodCollector collects terminated pods manifest and metadata
type TerminatedPodCollector struct {
	hostName          string
	clusterID         string
	sender            sender.Sender
	processor         *processors.Processor
	config            *oconfig.OrchestratorConfig
	systemInfo        *model.SystemInfo
	stopChan          chan struct{}
	workloadmetaStore workloadmeta.Component
	podBuffer         *terminatedPodBuffer
}

// NewTerminatedPodCollector creates a new TerminatedPodCollector
func NewTerminatedPodCollector(hostName, clusterID string, sender sender.Sender, processor *processors.Processor, config *oconfig.OrchestratorConfig, systemInfo *model.SystemInfo, workloadmetaStore workloadmeta.Component) *TerminatedPodCollector {
	c := &TerminatedPodCollector{
		hostName:          hostName,
		clusterID:         clusterID,
		sender:            sender,
		processor:         processor,
		config:            config,
		systemInfo:        systemInfo,
		stopChan:          make(chan struct{}),
		workloadmetaStore: workloadmetaStore,
	}
	c.podBuffer = newTerminatedPodBuffer(c.process)
	return c
}

// Run starts the terminated pod collection
// It will only start once and will not start if the feature is disabled
func (t *TerminatedPodCollector) Run() {
	if !pkgconfigsetup.Datadog().GetBool("orchestrator_explorer.terminated_resources.enabled") {
		return
	}

	startTerminatedPodsCollectionOnce.Do(func() {
		t.podBuffer.Start()
		go func() {
			filter := workloadmeta.NewFilterBuilder().
				SetSource(workloadmeta.SourceRemoteTerminatedPodCollector).
				SetEventType(workloadmeta.EventTypeUnset).
				AddKind(workloadmeta.KindKubernetesPod).
				Build()

			podEventsCh := t.workloadmetaStore.Subscribe(
				CheckName+"-terminated-resources",
				workloadmeta.NormalPriority,
				filter,
			)

			for {
				select {
				case eventBundle, ok := <-podEventsCh:
					if !ok {
						return
					}
					t.deletionHandler(eventBundle)
				case <-t.stopChan:
					return
				}
			}
		}()
	})
}

// Stop stops the terminated pod collection
func (t *TerminatedPodCollector) Stop() {
	log.Infof("Terminated pods collection stopped")
	close(t.stopChan)
	t.podBuffer.Stop()
}

// deletionHandler processes the pod deletion event and sends the metadata and manifest
func (t *TerminatedPodCollector) deletionHandler(evBundle workloadmeta.EventBundle) {
	evBundle.Acknowledge()

	pods := make([]*v1.Pod, 0, len(evBundle.Events))
	for _, event := range evBundle.Events {
		p, ok := event.Entity.(*workloadmeta.KubernetesPod)
		if !ok {
			log.Warnf("event entity is not a pod")
			continue
		}

		source := p.Manifest
		newPod := &v1.Pod{}
		err := json.Unmarshal(source, newPod)
		if err != nil {
			log.Errorf("failed to unmarshal pod source: %s, %s", err, string(source))
			continue
		}
		pods = append(pods, newPod)
	}

	t.podBuffer.append(pods...)
}

func (t *TerminatedPodCollector) process(pods []*v1.Pod) {
	if t.clusterID == "" {
		clusterID, err := clustername.GetClusterID()
		if err != nil {
			log.Warnf("failed to get cluster ID: %s", err)
			return
		}
		t.clusterID = clusterID
	}

	ctx := &processors.K8sProcessorContext{
		BaseProcessorContext: processors.BaseProcessorContext{
			Cfg:                  t.config,
			NodeType:             orchestrator.K8sPod,
			ClusterID:            t.clusterID,
			ManifestProducer:     true,
			IsTerminatedResource: true,
		},
		HostName:           t.hostName,
		ApiGroupVersionTag: "kube_api_version:v1",
		SystemInfo:         t.systemInfo,
	}

	processResult, processed := t.processor.Process(ctx, pods)
	if processed == -1 {
		log.Warn("unable to process pods: a panic occurred")
		return
	}

	t.sender.OrchestratorMetadata(processResult.MetadataMessages, t.clusterID, orchestrator.K8sPod)
	t.sender.OrchestratorManifest(processResult.ManifestMessages, t.clusterID)
}

var defaultFlushPodInterval = 10 * time.Second

type terminatedPodBuffer struct {
	in           chan *v1.Pod
	bufferedPods []*v1.Pod
	processFunc  func([]*v1.Pod)
	stopCh       chan struct{}
	wg           sync.WaitGroup
}

func newTerminatedPodBuffer(processFunc func([]*v1.Pod)) *terminatedPodBuffer {
	return &terminatedPodBuffer{
		in:           make(chan *v1.Pod, 100),
		bufferedPods: make([]*v1.Pod, 0, 100),
		stopCh:       make(chan struct{}),
		processFunc:  processFunc,
	}
}

// Start is to start a thread to buffer manifest and send them
// It flushes manifests every defaultFlushManifestTime
func (t *terminatedPodBuffer) Start() {
	t.wg.Add(1)

	go func() {
		ticker := time.NewTicker(defaultFlushPodInterval)
		defer func() {
			ticker.Stop()
			t.wg.Done()
		}()
	loop:
		for {
			select {
			case pod, ok := <-t.in:
				if !ok {
					log.Warnc("Fail to read pod from channel", orchestrator.ExtraLogContext...)
					continue
				}
				t.append(pod)
			case <-ticker.C:
				t.flush()
			case <-t.stopCh:
				t.flush()
				break loop
			}
		}
	}()
}

// flushManifest flushes manifests by chunking them first then sending them to the sender
func (t *terminatedPodBuffer) flush() {
	pods := t.bufferedPods
	t.processFunc(pods)
	t.bufferedPods = t.bufferedPods[:0]
}

// appendManifest appends manifest into the buffer
// If buffer is full, it will flush the buffer first then append the manifest
func (t *terminatedPodBuffer) append(pods ...*v1.Pod) {
	t.bufferedPods = append(t.bufferedPods, pods...)
}

// Stop is to kill the thread collecting manifest
func (t *terminatedPodBuffer) Stop() {
	t.stopCh <- struct{}{}
	t.wg.Wait()
}
