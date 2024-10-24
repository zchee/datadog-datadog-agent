// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build kubeapiserver && orchestrator

package k8s

import (
	"github.com/DataDog/datadog-agent/pkg/collector/corechecks/cluster/orchestrator/collectors"
	"github.com/DataDog/datadog-agent/pkg/collector/corechecks/cluster/orchestrator/processors"
	k8sProcessors "github.com/DataDog/datadog-agent/pkg/collector/corechecks/cluster/orchestrator/processors/k8s"
	"github.com/DataDog/datadog-agent/pkg/orchestrator"

	"k8s.io/apimachinery/pkg/labels"
	corev1Informers "k8s.io/client-go/informers/core/v1"
	corev1Listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
)

// NewPersistentVolumeCollectorVersions builds the group of collector versions.
func NewPersistentVolumeCollectorVersions() collectors.CollectorVersions {
	return collectors.NewCollectorVersions(
		NewPersistentVolumeCollector(),
	)
}

// PersistentVolumeCollector is a collector for Kubernetes PersistentVolumes.
type PersistentVolumeCollector struct {
	informer  corev1Informers.PersistentVolumeInformer
	lister    corev1Listers.PersistentVolumeLister
	metadata  *collectors.CollectorMetadata
	processor *processors.Processor
}

// NewPersistentVolumeCollector creates a new collector for the Kubernetes
// PersistentVolume resource.
func NewPersistentVolumeCollector() *PersistentVolumeCollector {
	return &PersistentVolumeCollector{
		metadata: &collectors.CollectorMetadata{
			IsDefaultVersion:                     true,
			IsStable:                             true,
			IsMetadataProducer:                   true,
			IsManifestProducer:                   true,
			SupportsManifestBuffering:            true,
			Name:                                 "persistentvolumes",
			NodeType:                             orchestrator.K8sPersistentVolume,
			Version:                              "v1",
			SupportsTerminatedResourceCollection: true,
		},
		processor: processors.NewProcessor(new(k8sProcessors.PersistentVolumeHandlers)),
	}
}

// Informer returns the shared informer.
func (c *PersistentVolumeCollector) Informer() cache.SharedInformer {
	return c.informer.Informer()
}

// Init is used to initialize the collector.
func (c *PersistentVolumeCollector) Init(rcfg *collectors.CollectorRunConfig) {
	c.informer = rcfg.OrchestratorInformerFactory.InformerFactory.Core().V1().PersistentVolumes()
	c.lister = c.informer.Lister()
}

// Metadata is used to access information about the collector.
func (c *PersistentVolumeCollector) Metadata() *collectors.CollectorMetadata {
	return c.metadata
}

// Run triggers the collection process.
func (c *PersistentVolumeCollector) Run(rcfg *collectors.CollectorRunConfig) (*collectors.CollectorRunResult, error) {
	list, err := c.lister.List(labels.Everything())
	if err != nil {
		return nil, collectors.NewListingError(err)
	}

	return c.Process(rcfg, list, false)
}

// Process is used to process the list of resources and return the result.
func (c *PersistentVolumeCollector) Process(rcfg *collectors.CollectorRunConfig, list interface{}, isTerminatedResource bool) (*collectors.CollectorRunResult, error) {
	ctx := collectors.NewK8sProcessorContext(rcfg, c.metadata, isTerminatedResource)

	processResult, processed := c.processor.Process(ctx, list)

	if processed == -1 {
		return nil, collectors.ErrProcessingPanic
	}

	result := &collectors.CollectorRunResult{
		Result:             processResult,
		ResourcesListed:    len(c.processor.Handlers().ResourceList(ctx, list)),
		ResourcesProcessed: processed,
	}

	return result, nil
}
