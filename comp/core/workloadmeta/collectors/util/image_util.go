// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2023-present Datadog, Inc.

// Package util contains utility functions for image metadata collection
package util

import (
	"github.com/DataDog/datadog-agent/comp/core/workloadmeta"
	"github.com/DataDog/datadog-agent/comp/trivy/trivy"
)

// UpdateSBOMRepoMetadata finds if the repo tags and repo digests are present in the SBOM and updates them if not.
// It returns a copy of the SBOM with the updated properties if they were not already present.
func UpdateSBOMRepoMetadata(sbom *workloadmeta.SBOM, repoTags, repoDigests []string) *workloadmeta.SBOM {
	return trivy.GetTrivyComponent().UpdateSBOMRepoMetadata(sbom, repoTags, repoDigests)
}
