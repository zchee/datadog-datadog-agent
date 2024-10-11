// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build kubeapiserver

// Package kubernetesaudit is a validation webhook that allows all pods into the cluster and generate a
// Datadog Event that will be used as a pseudo Audit Log.
package kubernetesaudit

import (
	"fmt"
	"time"

	admiv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/DataDog/datadog-agent/cmd/cluster-agent/admission"
	"github.com/DataDog/datadog-agent/comp/aggregator/demultiplexer"
	"github.com/DataDog/datadog-agent/pkg/clusteragent/admission/common"
	pkgconfigsetup "github.com/DataDog/datadog-agent/pkg/config/setup"
	"github.com/DataDog/datadog-agent/pkg/metrics/event"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

// Webhook is a validation webhook that allows all pods into the cluster.
type Webhook struct {
	name          string
	isEnabled     bool
	endpoint      string
	resources     map[string][]string
	operations    []admissionregistrationv1.OperationType
	demultiplexer demultiplexer.Component
}

// NewWebhook returns a new webhook
func NewWebhook(demultiplexer demultiplexer.Component) *Webhook {
	return &Webhook{
		name:      "kubernetes_audit",
		isEnabled: pkgconfigsetup.Datadog().GetBool("admission_controller.kubernetes_audit.enabled"),
		endpoint:  "/kubernetes-audit",
		// TODO (wassim): New resources implementation would look like this. Use `kubectl api-resources` to list all possible resources.
		resources: map[string][]string{
			"apps": {
				"deployments",
				"replicasets",
				"statefulsets",
			},
			"": {
				"pods",
			},
		},
		operations: []admissionregistrationv1.OperationType{
			//admissionregistrationv1.Create,
			//admissionregistrationv1.Update,
			admissionregistrationv1.Delete,
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
	// TODO (wassim): Improve the label selectors
	return nil, nil
}

// WebhookFunc returns the function that generates a Datadog Event and validates the request.
func (w *Webhook) WebhookFunc() admission.WebhookFunc {
	return func(request *admission.Request) *admiv1.AdmissionResponse {
		fmt.Println("Kubernetes Audit Event:", *request)
		fmt.Println("Kubernetes Audit Event Raw:", string(request.OldObject))

		// Validation must always return success.
		return &admiv1.AdmissionResponse{
			Allowed: true,
		}
	}
}

func (w *Webhook) emitEvent(request *admission.Request) {
	// Generate a Datadog Event.
	title := fmt.Sprintf("%s Event for %s/%s by %s", request.Operation, request.Namespace, request.Name, request.UserInfo.Username)
	text := fmt.Sprintf("%%%%%%\n"+
		"**Time:** %s\\\n"+
		"**User:** %s\\\n"+
		"**Resource:** %s/%s\\\n"+
		"**Operation:** %s\\\n"+
		"**Kind:** %s\\\n"+
		"**Request UID:** %s"+
		"\\\n%%%%%%",
		time.Now().UTC().Format("January 02, 2006 at 03:04:05 PM MST"),
		request.UserInfo.Username,
		request.Namespace,
		request.Name,
		request.Operation,
		request.Resource.Resource,
		request.UID,
	)
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

	e := event.Event{
		Title:          title,
		Text:           text,
		Ts:             0,
		Priority:       event.PriorityNormal,
		Tags:           tags,
		AlertType:      event.AlertTypeInfo,
		SourceTypeName: "kubernetes",
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
}
