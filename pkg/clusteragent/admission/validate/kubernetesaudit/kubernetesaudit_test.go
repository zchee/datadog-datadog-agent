// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build kubeapiserver

package kubernetesaudit

import (
	"encoding/json"
	"fmt"
	"github.com/DataDog/datadog-agent/cmd/cluster-agent/admission"
	"go.uber.org/fx"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/DataDog/datadog-agent/comp/aggregator/demultiplexer"
	"github.com/DataDog/datadog-agent/comp/aggregator/demultiplexer/demultiplexerimpl"
	"github.com/DataDog/datadog-agent/comp/core"
	"github.com/DataDog/datadog-agent/comp/core/config"
	"github.com/DataDog/datadog-agent/comp/core/hostname/hostnameimpl"
	"github.com/DataDog/datadog-agent/comp/core/log/def"
	logmock "github.com/DataDog/datadog-agent/comp/core/log/mock"
	"github.com/DataDog/datadog-agent/comp/serializer/compression/compressionimpl"
	"github.com/DataDog/datadog-agent/pkg/util/fxutil"
)

// TestKubernetesAuditWebhook tests the KubernetesAuditWebhook
func TestKubernetesAuditWebhook(t *testing.T) {
	demultiplexerMock := createDemultiplexer(t)
	datadogConfigMock := fxutil.Test[config.Component](t, core.MockBundle())
	datadogConfigMock.SetWithoutSource("admission_controller.kubernetes_audit.enabled", true)
	kubernetesAuditWebhook := NewWebhook(datadogConfigMock, demultiplexerMock)

	assert.True(t, kubernetesAuditWebhook.IsEnabled())
	assert.Equal(t, "kubernetes_audit", kubernetesAuditWebhook.name)
	userInfo := &authenticationv1.UserInfo{
		Username: "test",
	}
	object := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"kind": "Pod",
		},
	}
	oldObject := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"kind": "Pod",
		},
	}

	marshalledObject, err := json.Marshal(object)
	marshalledOldObject, err := json.Marshal(oldObject)

	request := admission.Request{
		UID:       "123",
		Name:      "test",
		Namespace: "test",
		Kind: metav1.GroupVersionKind{
			Group:   "",
			Version: "v1",
			Kind:    "Pod",
		},
		Resource: metav1.GroupVersionResource{
			Group:    "",
			Version:  "v1",
			Resource: "pods",
		},
		Operation:     "CREATE",
		UserInfo:      userInfo,
		Object:        marshalledObject,
		OldObject:     marshalledOldObject,
		DynamicClient: nil,
		APIClient:     nil,
	}
	validated, err := kubernetesAuditWebhook.emitEvent(&request, "", nil)
	assert.NoError(t, err)
	assert.True(t, validated)
	samples, timed := demultiplexerMock.WaitForSamples(1000)
	fmt.Printf("samples: %v\n", samples)
	fmt.Printf("timed: %v\n", timed)
	//assert.Error(t, err)
}

// createDemultiplexer creates a demultiplexer for testing
func createDemultiplexer(t *testing.T) demultiplexer.FakeSamplerMock {
	return fxutil.Test[demultiplexer.FakeSamplerMock](t, fx.Provide(func() log.Component { return logmock.New(t) }), compressionimpl.MockModule(), demultiplexerimpl.FakeSamplerMockModule(), hostnameimpl.MockModule())
}
