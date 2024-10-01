// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build kubeapiserver

// Package kubernetesaudit is a validation webhook that allows all pods into the cluster and generate a
// Datadog Event that will be used as a pseudo Audit Log.
package kubernetesaudit

import (
	"encoding/json"
	"fmt"
	"time"

	admiv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/dynamic"

	"github.com/DataDog/datadog-agent/cmd/cluster-agent/admission"
	"github.com/DataDog/datadog-agent/comp/core/config"
	"github.com/DataDog/datadog-agent/pkg/aggregator"
	"github.com/DataDog/datadog-agent/pkg/clusteragent/admission/common"
	validatecommon "github.com/DataDog/datadog-agent/pkg/clusteragent/admission/validate/common"
	"github.com/DataDog/datadog-agent/pkg/metrics/event"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

// Webhook is a validation webhook that allows all pods into the cluster.
type Webhook struct {
	name            string
	isEnabled       bool
	endpoint        string
	resources       map[string][]string
	operations      []admissionregistrationv1.OperationType
	matchConditions []admissionregistrationv1.MatchCondition
	demultiplexer   aggregator.Demultiplexer
}

// NewWebhook returns a new webhook
func NewWebhook(datadogConfig config.Component, demultiplexer aggregator.Demultiplexer) *Webhook {
	return &Webhook{
		name:      "kubernetes_audit",
		isEnabled: datadogConfig.GetBool("admission_controller.kubernetes_audit.enabled"),
		endpoint:  "/kubernetes-audit",
		resources: map[string][]string{
			"apps": {
				"deployments",
			},
		},
		operations: []admissionregistrationv1.OperationType{
			admissionregistrationv1.OperationAll,
		},
		matchConditions: []admissionregistrationv1.MatchCondition{
			{
				Name:       "exclude-system-users",
				Expression: "!(request.userInfo.username.startsWith('system:'))",
			},
		},
		demultiplexer: demultiplexer,
	}
}

// Name returns the name of the webhook
func (w *Webhook) Name() string {
	return w.name
}

// WebhookType returns the type of the webhook
func (w *Webhook) WebhookType() common.WebhookType {
	return common.ValidatingWebhook
}

// IsEnabled returns whether the webhook is enabled
func (w *Webhook) IsEnabled() bool {
	return w.isEnabled
}

// Endpoint returns the endpoint of the webhook
func (w *Webhook) Endpoint() string {
	return w.endpoint
}

// Resources returns the kubernetes resources for which the webhook should
// be invoked
func (w *Webhook) Resources() map[string][]string {
	return w.resources
}

// Operations returns the operations on the resources specified for which
// the webhook should be invoked
func (w *Webhook) Operations() []admissionregistrationv1.OperationType {
	return w.operations
}

// LabelSelectors returns the label selectors that specify when the webhook
// should be invoked
func (w *Webhook) LabelSelectors(useNamespaceSelector bool) (namespaceSelector *metav1.LabelSelector, objectSelector *metav1.LabelSelector) {
	return common.DefaultLabelSelectors(useNamespaceSelector)
}

// MatchConditions returns the Match Conditions used for fine-grained
// request filtering
func (w *Webhook) MatchConditions() []admissionregistrationv1.MatchCondition {
	return w.matchConditions
}

// WebhookFunc returns the function that generates a Datadog Event and validates the request.
func (w *Webhook) WebhookFunc() admission.WebhookFunc {
	return func(request *admission.Request) *admiv1.AdmissionResponse {
		return common.ValidationResponse(validatecommon.Validate(request, w.Name(), w.emitEvent, request.DynamicClient))
	}
}

// emitEvent generates a Datadog Event, sends it to the default sender and validates the request.
func (w *Webhook) emitEvent(request *admission.Request, _ string, _ dynamic.Interface) (bool, error) {
	// Decode object and oldObject.
	var newResource unstructured.Unstructured
	if request.Operation != admissionregistrationv1.Delete {
		if err := json.Unmarshal(request.Object, &newResource); err != nil {
			return true, fmt.Errorf("failed to unmarshal object: %w", err)
		}
	}
	var oldResource unstructured.Unstructured
	if request.Operation != "CREATE" && request.Operation != "CONNECT" {
		if err := json.Unmarshal(request.OldObject, &oldResource); err != nil {
			return true, fmt.Errorf("failed to unmarshal oldObject: %w", err)
		}
	}

	// Generate a Datadog Event.
	title := fmt.Sprintf("%s Event for %s %s/%s by %s", request.Operation, request.Kind.Kind, request.Namespace, request.Name, request.UserInfo.Username)
	text := "%%%" +
		"**Resource:** " + request.Namespace + "/" + request.Name + "\\\n" +
		"**Username:** " + request.UserInfo.Username + "\\\n" +
		"**Operation:** " + string(request.Operation) + "\\\n" +
		"**Kind:** " + request.Kind.Kind + "\\\n" +
		"**Time:** " + time.Now().UTC().Format("January 02, 2006 at 03:04:05 PM MST") + "\\\n" +
		"**Request UID:** " + string(request.UID) +
		"%%%"

	tags := []string{
		"uid:" + string(request.UID),
		"username:" + request.UserInfo.Username,
		"kind:" + request.Kind.Kind,
		"namespace:" + request.Namespace,
		"name:" + request.Name,
		"operation:" + string(request.Operation),
		"resource:" + request.Resource.Resource,
		"wassim:debug", // TODO (wassim): remove this tag
	}

	// Add labels to the tags.
	for key, value := range newResource.GetLabels() {
		tags = append(tags, fmt.Sprintf("%s:%s", key, value))
	}
	for key, value := range oldResource.GetLabels() {
		tags = append(tags, fmt.Sprintf("%s:%s", key, value))
	}

	e := event.Event{
		Title:          title,
		Text:           text,
		Ts:             0,
		Priority:       event.PriorityNormal,
		Tags:           tags,
		AlertType:      event.AlertTypeInfo,
		SourceTypeName: "kubernetes", // TODO (wassim): Replace with kubernetes_audit_webhook.
		EventType:      "kubernetes_audit",
	}

	// Send the event to the default sender.
	s, err := w.demultiplexer.GetDefaultSender()
	if err != nil {
		_ = log.Errorf("Error getting the default sender: %s", err)
	} else {
		log.Debugf("Sending Kubernetes Audit Event: %v", e)
		s.Event(e)
	}

	// Validation must always validate incoming request.
	return true, nil
}
