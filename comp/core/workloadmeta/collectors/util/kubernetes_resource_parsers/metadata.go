// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build kubeapiserver

package kubernetesresourceparsers

import (
	"github.com/DataDog/datadog-agent/comp/core/workloadmeta/collectors/util"
	workloadmeta "github.com/DataDog/datadog-agent/comp/core/workloadmeta/def"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"regexp"
	"sync"
)

type metadataParser struct {
	gvr               *schema.GroupVersionResource
	annotationsFilter []*regexp.Regexp
}

var (
	uidToResourceMap = make(map[types.UID]string)
	mapMutex         sync.RWMutex
)

// NewMetadataParser initialises and returns a metadata parser
func NewMetadataParser(gvr schema.GroupVersionResource, annotationsExclude []string) (ObjectParser, error) {
	filters, err := parseFilters(annotationsExclude)
	if err != nil {
		return nil, err
	}

	return metadataParser{gvr: &gvr, annotationsFilter: filters}, nil
}

func (p metadataParser) Parse(obj interface{}) workloadmeta.Entity {
	partialObjectMetadata := obj.(*metav1.PartialObjectMetadata)
	id := util.GenerateKubeMetadataEntityID(p.gvr.Group, p.gvr.Resource, partialObjectMetadata.Namespace, partialObjectMetadata.Name)
	addToUIDToResourceMap(partialObjectMetadata.UID, p.gvr.Resource)

	return &workloadmeta.KubernetesMetadata{
		EntityID: workloadmeta.EntityID{
			Kind: workloadmeta.KindKubernetesMetadata,
			ID:   string(id),
		},
		EntityMeta: workloadmeta.EntityMeta{
			Name:        partialObjectMetadata.Name,
			Namespace:   partialObjectMetadata.Namespace,
			Labels:      partialObjectMetadata.Labels,
			Annotations: filterMapStringKey(partialObjectMetadata.Annotations, p.annotationsFilter),
		},
		GVR: p.gvr,
	}
}

func addToUIDToResourceMap(uid types.UID, resource string) {
	mapMutex.Lock()
	defer mapMutex.Unlock()

	uidToResourceMap[uid] = resource
}

// GetResourceFromUID returns the resource from the mapped UID
func GetResourceFromUID(uid types.UID) (string, bool) {
	mapMutex.RLock()
	defer mapMutex.RUnlock()

	resource, found := uidToResourceMap[uid]
	return resource, found
}

// GetUIDToResourceMap returns the map
func GetUIDToResourceMap() map[types.UID]string {
	return uidToResourceMap
}
