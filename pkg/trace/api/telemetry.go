// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2022-present Datadog, Inc.

package api

import (
	"bytes"
	"fmt"
	"io"
	stdlog "log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/DataDog/datadog-agent/pkg/trace/api/internal/header"
	"github.com/DataDog/datadog-agent/pkg/trace/config"
	"github.com/DataDog/datadog-agent/pkg/trace/log"

	"github.com/DataDog/datadog-go/v5/statsd"
)

const functionARNKeyTag = "function_arn"
const originTag = "origin"

type cloudResourceType string
type cloudProvider string

const (
	awsLambda                     cloudResourceType = "AWSLambda"
	awsFargate                    cloudResourceType = "AWSFargate"
	cloudRun                      cloudResourceType = "GCPCloudRun"
	azureAppService               cloudResourceType = "AzureAppService"
	azureContainerApp             cloudResourceType = "AzureContainerApp"
	aws                           cloudProvider     = "AWS"
	gcp                           cloudProvider     = "GCP"
	azure                         cloudProvider     = "Azure"
	cloudProviderHeader           string            = "dd-cloud-provider"
	cloudResourceTypeHeader       string            = "dd-cloud-resource-type"
	cloudResourceIdentifierHeader string            = "dd-cloud-resource-identifier"
)

// telemetryMultiTransport sends HTTP requests to multiple targets using an
// underlying http.RoundTripper. API keys are set separately for each target.
// The target hostname
// When multiple endpoints are in use the response from the main endpoint
// is proxied back to the client, while for all aditional endpoints the
// response is discarded. There is no de-duplication done between endpoint
// hosts or api keys.
//
// Could be extended in the future to allow supporting more product endpoints
// by simply parametrizing metric tags, and logger names
type telemetryMultiTransport struct {
	Transport http.RoundTripper
	Endpoints []*config.Endpoint
	statsd    statsd.ClientInterface
}

// telemetryProxyHandler parses returns a new HTTP handler which will proxy requests to the configured intakes.
// If the main intake URL can not be computed because of config, the returned handler will always
// return http.StatusInternalServerError along with a clarification.
func (r *HTTPReceiver) telemetryProxyHandler() http.Handler {
	// extract and validate Hostnames from configured endpoints
	var endpoints []*config.Endpoint
	for _, endpoint := range r.conf.TelemetryConfig.Endpoints {
		u, err := url.Parse(endpoint.Host)
		if err != nil {
			log.Errorf("Error parsing apm_config.telemetry endpoint %q: %v", endpoint.Host, err)
			continue
		}
		if u.Host != "" {
			endpoint.Host = u.Host
		}

		endpoints = append(endpoints, endpoint)
	}

	if len(endpoints) == 0 {
		log.Error("None of the configured apm_config.telemetry endpoints are valid. Telemetry proxy is off")
		return http.NotFoundHandler()
	}

	forwarder := r.telemetryForwarder
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// Read at most maxInflightBytes since we're going to throw out the result anyway if it's bigger
		body, err := io.ReadAll(io.LimitReader(r.Body, forwarder.maxInflightBytes+1))
		if err != nil {
			writeEmptyJSON(w, http.StatusInternalServerError)
			return
		}

		containerID := r.containerIDProvider.GetContainerID(req.Context(), req.Header)
		if containerID == "" {
			_ = r.statsd.Count("datadog.trace_agent.telemetry_proxy.no_container_id_found", 1, []string{}, 1)
		}
		containerTags := getContainerTags(r.conf.ContainerTags, containerID)

		newReq, err := http.NewRequestWithContext(forwarder.cancelCtx, r.Method, r.URL.String(), bytes.NewBuffer(body))
		if err != nil {
			writeEmptyJSON(w, http.StatusInternalServerError)
			return
		}
		newReq.Header = r.Header.Clone()
		select {
		case forwarder.forwardedReqChan <- forwardedRequest{
			req:  newReq,
			body: body,
		}:
			writeEmptyJSON(w, http.StatusOK)
		default:
			writeEmptyJSON(w, http.StatusTooManyRequests)
		}
	}
	return &httputil.ReverseProxy{
		Director:  director,
		ErrorLog:  logger,
		Transport: &transport,
	}
}

func extractFargateTask(containerTags string) (string, bool) {
	return extractTag(containerTags, "task_arn")
}

func extractTag(tags string, name string) (string, bool) {
	leftoverTags := tags
	for {
		if leftoverTags == "" {
			return "", false
		}
		var tag string
		tag, leftoverTags, _ = strings.Cut(leftoverTags, ",")

		tagName, value, hasValue := strings.Cut(tag, ":")
		if hasValue && tagName == name {
			return value, true
		}
	}
}

// RoundTrip sends request first to Endpoint[0], then sends a copy of main request to every configurged
// additional endpoint.
//
// All requests will be sent irregardless of any errors
// If any request fails, the error will be logged.
func (f *TelemetryForwarder) forwardTelemetry(req forwardedRequest) {
	defer f.endRequest(req)

	f.setRequestHeader(req.req)

	for i, e := range f.endpoints {
		var newReq *http.Request
		if i != len(f.endpoints)-1 {
			newReq = req.req.Clone(req.req.Context())
		} else {
			// don't clone the request for the last endpoint since we can use the
			// one provided in args.
			newReq = req.req
		}
		newReq.Body = io.NopCloser(bytes.NewReader(req.body))

		if resp, err := f.forwardTelemetryEndpoint(newReq, e); err == nil {
			if !(200 <= resp.StatusCode && resp.StatusCode < 300) {
				f.logger.Error("Received unexpected status code %v", resp.StatusCode)
			}
			io.Copy(io.Discard, resp.Body) // nolint:errcheck
			resp.Body.Close()
		} else {
			log.Error(err)
		}
	}
	return rresp, rerr
}

func (m *telemetryMultiTransport) roundTrip(req *http.Request, endpoint *config.Endpoint) (*http.Response, error) {
	tags := []string{
		fmt.Sprintf("endpoint:%s", endpoint.Host),
	}
	defer func(now time.Time) {
		_ = m.statsd.Timing("datadog.trace_agent.telemetry_proxy.roundtrip_ms", time.Since(now), tags, 1)
	}(time.Now())

	req.Host = endpoint.Host
	req.URL.Host = endpoint.Host
	req.URL.Scheme = "https"
	req.Header.Set("DD-API-KEY", endpoint.APIKey)

	resp, err := m.Transport.RoundTrip(req)
	if err != nil {
		_ = m.statsd.Count("datadog.trace_agent.telemetry_proxy.error", 1, tags, 1)
	}
	return resp, err
}
