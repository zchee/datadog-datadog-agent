// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build kubeapiserver

// Package webhook implements the webhook controller of the Cluster Agent's
// Admission Controller.
package webhook

import (
	"fmt"
	"strings"

	pkgconfigsetup "github.com/DataDog/datadog-agent/pkg/config/setup"
	"github.com/DataDog/datadog-agent/pkg/util/kubernetes/apiserver/common"
)

// Config contains config parameters
// of the webhook controller
type Config struct {
	webhookName              string
	secretName               string
	namespace                string
	admissionV1Enabled       bool
	namespaceSelectorEnabled bool
	svcName                  string
	svcPort                  int32
	timeout                  int32
	failurePolicy            string
	reinvocationPolicy       string
}

// NewConfig creates a webhook controller configuration
func NewConfig(admissionV1Enabled, namespaceSelectorEnabled bool) Config {
	return Config{
		webhookName:              pkgconfigsetup.Datadog().GetString("admission_controller.webhook_name"),
		secretName:               pkgconfigsetup.Datadog().GetString("admission_controller.certificate.secret_name"),
		namespace:                common.GetResourcesNamespace(),
		admissionV1Enabled:       admissionV1Enabled,
		namespaceSelectorEnabled: namespaceSelectorEnabled,
		svcName:                  pkgconfigsetup.Datadog().GetString("admission_controller.service_name"),
		svcPort:                  int32(443),
		timeout:                  pkgconfigsetup.Datadog().GetInt32("admission_controller.timeout_seconds"),
		failurePolicy:            pkgconfigsetup.Datadog().GetString("admission_controller.failure_policy"),
		reinvocationPolicy:       pkgconfigsetup.Datadog().GetString("admission_controller.reinvocation_policy"),
	}
}

func (w *Config) getWebhookName() string        { return w.webhookName }
func (w *Config) getSecretName() string         { return w.secretName }
func (w *Config) getSecretNs() string           { return w.namespace }
func (w *Config) useAdmissionV1() bool          { return w.admissionV1Enabled }
func (w *Config) useNamespaceSelector() bool    { return w.namespaceSelectorEnabled }
func (w *Config) getServiceNs() string          { return w.namespace }
func (w *Config) getServiceName() string        { return w.svcName }
func (w *Config) getServicePort() int32         { return w.svcPort }
func (w *Config) getTimeout() int32             { return w.timeout }
func (w *Config) getFailurePolicy() string      { return w.failurePolicy }
func (w *Config) getReinvocationPolicy() string { return w.reinvocationPolicy }
func (w *Config) configName(suffix string) string {
	name := strings.ReplaceAll(fmt.Sprintf("%s.%s", w.webhookName, suffix), "-", ".")
	name = strings.ReplaceAll(name, "_", ".")
	return name
}
