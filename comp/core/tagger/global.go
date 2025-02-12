// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package tagger

import (
	"errors"
	"sync"

	"github.com/DataDog/datadog-agent/comp/core/tagger/common"
	"github.com/DataDog/datadog-agent/comp/core/tagger/types"
	taggertypes "github.com/DataDog/datadog-agent/pkg/tagger/types"
	"github.com/DataDog/datadog-agent/pkg/tagset"
)

var (
	// globalTagger is the global tagger instance backing the global Tag functions
	// // TODO(components) (tagger): globalTagger is a legacy global variable but still in use, to be eliminated
	globalTagger Component

	// initOnce ensures that the global tagger is only initialized once.  It is reset every
	// time the default tagger is set.
	initOnce sync.Once
)

// SetGlobalTaggerClient sets the global taggerClient instance
func SetGlobalTaggerClient(t Component) {
	initOnce.Do(func() {
		globalTagger = t
	})
}

// UnlockGlobalTaggerClient releases the initOnce lock on the global tagger. For testing only.
func UnlockGlobalTaggerClient() {
	initOnce = sync.Once{}
}

// GetEntity returns the hash for the provided entity id.
func GetEntity(entityID types.EntityID) (*types.Entity, error) {
	if globalTagger == nil {
		return nil, errors.New("a global tagger must be set before calling GetEntity")
	}
	return globalTagger.GetEntity(entityID)
}

// LegacyTag is an interface function that queries taggerclient singleton
// If possible, avoid using this function, and use the Tag interface function instead.
// This function exists in order not to break backward compatibility with rtloader and python
// integrations using the tagger
func LegacyTag(entity string, cardinality types.TagCardinality) ([]string, error) {
	if globalTagger == nil {
		return nil, errors.New("a global tagger must be set before calling Tag")
	}

	prefix, id, err := common.ExtractPrefixAndID(entity)
	if err != nil {
		return nil, err
	}

	entityID := types.NewEntityID(prefix, id)
	return globalTagger.Tag(entityID, cardinality)
}

// Tag is an interface function that queries taggerclient singleton
func Tag(entity types.EntityID, cardinality types.TagCardinality) ([]string, error) {
	if globalTagger == nil {
		return nil, errors.New("a global tagger must be set before calling Tag")
	}
	return globalTagger.Tag(entity, cardinality)
}

// GetEntityHash is an interface function that queries taggerclient singleton
func GetEntityHash(entityID types.EntityID, cardinality types.TagCardinality) string {
	if globalTagger != nil {
		return globalTagger.GetEntityHash(entityID, cardinality)
	}
	return ""
}

// AgentTags is an interface function that queries taggerclient singleton
func AgentTags(cardinality types.TagCardinality) ([]string, error) {
	if globalTagger == nil {
		return nil, errors.New("a global tagger must be set before calling AgentTags")
	}
	return globalTagger.AgentTags(cardinality)
}

// GlobalTags is an interface function that queries taggerclient singleton
func GlobalTags(cardinality types.TagCardinality) ([]string, error) {
	if globalTagger == nil {
		return nil, errors.New("a global tagger must be set before calling GlobalTags")
	}
	return globalTagger.GlobalTags(cardinality)
}

// List the content of the defaulTagger
func List() types.TaggerListResponse {
	if globalTagger != nil {
		return globalTagger.List()
	}
	return types.TaggerListResponse{}
}

// SetNewCaptureTagger will set capture tagger in global tagger instance by using provided capture tagger
func SetNewCaptureTagger(newCaptureTagger Component) {
	if globalTagger != nil {
		globalTagger.SetNewCaptureTagger(newCaptureTagger)
	}
}

// ResetCaptureTagger will reset capture tagger
func ResetCaptureTagger() {
	if globalTagger != nil {
		globalTagger.ResetCaptureTagger()
	}
}

// EnrichTags is an interface function that queries taggerclient singleton
func EnrichTags(tb tagset.TagsAccumulator, originInfo taggertypes.OriginInfo) {
	if globalTagger != nil {
		globalTagger.EnrichTags(tb, originInfo)
	}
}

// ChecksCardinality is an interface function that queries taggerclient singleton
func ChecksCardinality() types.TagCardinality {
	if globalTagger != nil {
		return globalTagger.ChecksCardinality()
	}
	return types.LowCardinality
}

// DogstatsdCardinality is an interface function that queries taggerclient singleton
func DogstatsdCardinality() types.TagCardinality {
	if globalTagger != nil {
		return globalTagger.DogstatsdCardinality()
	}
	return types.LowCardinality
}
