// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build kubeapiserver

package kubernetesaudit

import (
	"testing"
)

func TestInjectHostIP(t *testing.T) {
	return
	/*
		demultiplexer := fxutil.Test[demultiplexer.Component](t, core.MockBundle())
		datadogConfig := fxutil.Test[config.Component](t, core.MockBundle())
		webhook := NewWebhook(datadogConfig, demultiplexer)
		validationFunction := webhook.WebhookFunc
		validationFunction()

		validation, err := validationFunction()
		assert.Nil(t, err)
		assert.True(t, validation)
		// TODO (wassim): Validate that we get the event.
	*/
}
