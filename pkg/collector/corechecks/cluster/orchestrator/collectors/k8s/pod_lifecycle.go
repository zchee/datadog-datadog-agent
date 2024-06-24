// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build kubeapiserver && orchestrator

package k8s

import (
	"fmt"

	"github.com/davecgh/go-spew/spew"

	"github.com/DataDog/datadog-agent/pkg/collector/corechecks/cluster/orchestrator/collectors"
	"github.com/DataDog/datadog-agent/pkg/collector/corechecks/cluster/orchestrator/processors"
	k8sProcessors "github.com/DataDog/datadog-agent/pkg/collector/corechecks/cluster/orchestrator/processors/k8s"
	"github.com/DataDog/datadog-agent/pkg/orchestrator"
	"github.com/DataDog/datadog-agent/pkg/util/log"

	corev1Informers "k8s.io/client-go/informers/core/v1"
	corev1Listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
)

type PodLifecycleEventHandler struct{}

func (h *PodLifecycleEventHandler) OnAdd(obj interface{}, isInInitialList bool) {
	log.Infof("Pod added: %s", spew.Sdump(obj))
}

func (h *PodLifecycleEventHandler) OnUpdate(oldObj, newObj interface{}) {
	log.Infof("Pod updated: %s", spew.Sdump(newObj))
}

func (h *PodLifecycleEventHandler) OnDelete(obj interface{}) {
	log.Infof("Pod deleted: %s", spew.Sdump(obj))
}

// NewPodLifecycleEventCollectorVersions builds the group of collector versions.
func NewPodLifecycleEventCollectorVersions() collectors.CollectorVersions {
	return collectors.NewCollectorVersions(
		NewPodLifecycleEventCollector(),
	)
}

// PodLifecycleEventCollector is a collector for Kubernetes Pods that are not
// assigned to a node yet.
type PodLifecycleEventCollector struct {
	informer  corev1Informers.PodInformer
	lister    corev1Listers.PodLister
	metadata  *collectors.CollectorMetadata
	processor *processors.Processor
}

// NewPodLifecycleEventCollector creates a new collector for lifecycle events of the Kubernetes Pod resource.
func NewPodLifecycleEventCollector() *PodLifecycleEventCollector {
	return &PodLifecycleEventCollector{
		metadata: &collectors.CollectorMetadata{
			IsDefaultVersion:          true,
			IsStable:                  true,
			IsMetadataProducer:        true,
			IsManifestProducer:        true,
			SupportsManifestBuffering: true,
			Name:                      "pods",
			NodeType:                  orchestrator.K8sPod,
			Version:                   "v1",
		},
		processor: processors.NewProcessor(new(k8sProcessors.PodHandlers)),
	}
}

// Informer returns the shared informer.
func (c *PodLifecycleEventCollector) Informer() cache.SharedInformer {
	return c.informer.Informer()
}

// Init is used to initialize the collector.
func (c *PodLifecycleEventCollector) Init(rcfg *collectors.CollectorRunConfig) {
	c.informer = rcfg.OrchestratorInformerFactory.InformerFactory.Core().V1().Pods()
	_, err := c.informer.Informer().AddEventHandler(new(PodLifecycleEventHandler))
	if err != nil {
		log.Errorf("error adding event handler", err)
	}
}

// Metadata is used to access information about the collector.
func (c *PodLifecycleEventCollector) Metadata() *collectors.CollectorMetadata {
	return c.metadata
}

// Run triggers the collection process.
func (c *PodLifecycleEventCollector) Run(rcfg *collectors.CollectorRunConfig) (*collectors.CollectorRunResult, error) {
	return nil, fmt.Errorf("this check returns an error on purpose")
}
