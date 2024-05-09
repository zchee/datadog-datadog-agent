// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build kubeapiserver

package autoinstrumentation

import (
	"strconv"
	"strings"

	"github.com/DataDog/datadog-agent/pkg/clusteragent/admission/common"
	"github.com/DataDog/datadog-agent/pkg/clusteragent/telemetry"
	"github.com/DataDog/datadog-agent/pkg/remoteconfig/state"
)

// TargetObjKind represents the supported k8s object kinds
type TargetObjKind string

const (
	// KindCluster refers to k8s clusters
	KindCluster TargetObjKind = "cluster"
)

// Action is the action requested by the user
type Action string

const (
	// EnableConfig instructs the patcher to apply the patch request
	EnableConfig Action = "enable"
)

// Request holds the required data to target a k8s object and apply library configuration
type Request struct {
	ID            string `json:"id"`
	Revision      int64  `json:"revision"`
	RcVersion     uint64 `json:"rc_version"`
	SchemaVersion string `json:"schema_version"`
	Action        Action `json:"action"`

	// Library parameters
	LibConfig common.LibConfig `json:"lib_config"`

	K8sTargetV2 *K8sTargetV2 `json:"k8s_target_v2,omitempty"`
}

// K8sClusterTarget represents k8s target within a cluster
type K8sClusterTarget struct {
	ClusterName       string    `json:"cluster_name"`
	Enabled           *bool     `json:"enabled,omitempty"`
	EnabledNamespaces *[]string `json:"enabled_namespaces,omitempty"`
}

// K8sTargetV2 represent the targetet k8s scope
type K8sTargetV2 struct {
	ClusterTargets []K8sClusterTarget `json:"cluster_targets"`
}

// Response represents the result of applying RC config
type Response struct {
	ID        string            `json:"id"`
	Revision  int64             `json:"revision"`
	RcVersion uint64            `json:"rc_version"`
	Status    state.ApplyStatus `json:"status"`
}

func (req Request) getApmRemoteConfigEvent(err error, errorCode int) telemetry.ApmRemoteConfigEvent {
	env := ""
	if req.LibConfig.Env != nil {
		env = *req.LibConfig.Env
	}
	errorMessage := ""
	if err != nil {
		errorMessage = err.Error()
	}
	targetClusters := []string{}
	targetNamespaces := []string{}
	targetEnabled := []string{}
	for _, c := range req.K8sTargetV2.ClusterTargets {
		targetClusters = append(targetClusters, c.ClusterName)
		if c.EnabledNamespaces != nil && len(*c.EnabledNamespaces) > 0 {
			targetNamespaces = append(targetNamespaces, *c.EnabledNamespaces...)
		}
		if c.Enabled != nil {
			targetEnabled = append(targetEnabled, strconv.FormatBool(*c.Enabled))
		}
	}
	return telemetry.ApmRemoteConfigEvent{
		RequestType: "apm-remote-config-event",
		ApiVersion:  "v2",
		Payload: telemetry.ApmRemoteConfigEventPayload{
			Tags: telemetry.ApmRemoteConfigEventTags{
				Env:                 env,
				RcId:                req.ID,
				RcRevision:          req.Revision,
				RcVersion:           req.RcVersion,
				KubernetesCluster:   strings.Join(targetClusters, " "),
				KubernetesNamespace: strings.Join(targetNamespaces, " "),
				KubernetesKind:      "cluster",
				KubernetesName:      strings.Join(targetEnabled, " "),
			},
			Error: telemetry.ApmRemoteConfigEventError{
				Code:    errorCode,
				Message: errorMessage,
			},
		},
	}
}
