// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package util

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/DataDog/datadog-agent/comp/core/config"
	pkgconfigsetup "github.com/DataDog/datadog-agent/pkg/config/setup"
)

// ShouldCloseConnection is an option to DoGet to indicate whether to close the underlying
// connection after reading the response
type ShouldCloseConnection int

const (
	// LeaveConnectionOpen keeps the underlying connection open after reading the request response
	LeaveConnectionOpen ShouldCloseConnection = iota
	// CloseConnection closes the underlying connection after reading the request response
	CloseConnection
)

// ReqOptions are options when making a request
type ReqOptions struct {
	Conn      ShouldCloseConnection
	Ctx       context.Context
	Authtoken string
}

// type AgentAdress struct {
// 	Cmd    string
// 	Expvar string
// }

type DialBookBuilder struct {
	config config.Reader
	host   string
	addr   map[string]string
	err    error
}

type dialBook map[string]string

const (
	CoreCmd    = "core-cmd"
	CoreExpvar = "core-expvar"

	TraceCmd    = "trace-cmd"
	TraceExpvar = "trace-expvar"

	SecurityCmd    = "security-cmd"
	SecurityExpvar = "security-expvar"

	ProcessCmd    = "process-agent"
	ProcessExpvar = "process-expvar"

	ClusterAgent = "cluster-agent"
)

type dialContext func(ctx context.Context, network string, addr string) (net.Conn, error)

func NewDialBookBuilder(config config.Reader) DialBookBuilder {
	coreAgentAddress, err := pkgconfigsetup.GetIPCAddress(config)

	return DialBookBuilder{
		config: config,
		host:   coreAgentAddress,
		addr:   make(map[string]string),
		err:    err,
	}
}

func (a DialBookBuilder) WithCore() DialBookBuilder {
	// If AgentAdress is erroneous, return
	if a.err != nil {
		return a
	}

	a.addr[CoreCmd] = net.JoinHostPort(a.host, a.config.GetString("cmd_port"))
	a.addr[CoreExpvar] = net.JoinHostPort(a.host, a.config.GetString("expvar_port"))

	return a
}

func (a DialBookBuilder) WithTrace() DialBookBuilder {
	// If AgentAdress is erroneous, return
	if a.err != nil {
		return a
	}

	a.addr[TraceCmd] = net.JoinHostPort(a.host, a.config.GetString("apm_config.debug.port"))
	a.addr[TraceExpvar] = net.JoinHostPort(a.host, a.config.GetString("apm_config.debug.port"))

	return a
}

func (a DialBookBuilder) WithProcess() DialBookBuilder {
	// If AgentAdress is erroneous, return
	if a.err != nil {
		return a
	}

	processAgentAddressPort, err := pkgconfigsetup.GetProcessAPIAddressPort(a.config)
	if err != nil {
		a.err = err
		return a
	}

	a.addr[ProcessCmd] = processAgentAddressPort
	a.addr[ProcessExpvar] = net.JoinHostPort(a.host, a.config.GetString("process_config.expvar_port"))

	return a
}

func (a DialBookBuilder) WithSecurity() DialBookBuilder {
	// If AgentAdress is erroneous, return
	if a.err != nil {
		return a
	}

	securityAgentAddressPort, err := pkgconfigsetup.GetSecurityAgentAPIAddressPort(a.config)
	if err != nil {
		a.err = err
		return a
	}

	a.addr[SecurityCmd] = securityAgentAddressPort
	a.addr[SecurityExpvar] = net.JoinHostPort(a.host, a.config.GetString("security_agent.expvar_port"))

	return a
}

func (a DialBookBuilder) WithCluster() DialBookBuilder {
	// If AgentAdress is erroneous, return
	if a.err != nil {
		return a
	}

	a.addr[ClusterAgent] = net.JoinHostPort(a.host, a.config.GetString("cluster_agent.cmd_port"))

	return a
}

func (a DialBookBuilder) Build() (dialBook, error) {
	if a.err != nil {
		return nil, a.err
	}

	return a.addr, nil
}

func NewDefaultDialBook(config config.Reader) (dialBook, error) {
	return NewDialBookBuilder(config).WithCore().WithTrace().WithProcess().WithSecurity().WithCluster().Build()
}

type ClientBuilder struct {
	tr      *http.Transport
	timeout time.Duration
}

// GetClient is a convenience function returning an http client
// `GetClient(false)` must be used only for HTTP requests whose destination is
// localhost (ie, for Agent commands).
func GetClient() ClientBuilder {
	return ClientBuilder{
		tr: &http.Transport{},
	}
}

func (c ClientBuilder) WithNoVerify() ClientBuilder {
	c.tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	return c
}

func (c ClientBuilder) WithTimeout(to time.Duration) ClientBuilder {
	c.timeout = to
	return c
}

func (c ClientBuilder) WithResolver(d dialBook) ClientBuilder {
	c.tr.DialContext = getDialContext(
		func() dialBook {
			return d
		})

	return c
}

func (c ClientBuilder) Build() *http.Client {
	return &http.Client{
		Transport: c.tr,
		Timeout:   c.timeout,
	}
}

// DoGet is a wrapper around performing HTTP GET requests
func DoGet(c *http.Client, url string, conn ShouldCloseConnection) (body []byte, e error) {
	return DoGetWithOptions(c, url, &ReqOptions{Conn: conn})
}

// DoGetWithOptions is a wrapper around performing HTTP GET requests
func DoGetWithOptions(c *http.Client, url string, options *ReqOptions) (body []byte, e error) {
	if options.Authtoken == "" {
		options.Authtoken = GetAuthToken()
	}

	if options.Ctx == nil {
		options.Ctx = context.Background()
	}

	req, e := http.NewRequestWithContext(options.Ctx, "GET", url, nil)
	if e != nil {
		return body, e
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+options.Authtoken)
	if options.Conn == CloseConnection {
		req.Close = true
	}

	r, e := c.Do(req)
	if e != nil {
		return body, e
	}
	body, e = io.ReadAll(r.Body)
	r.Body.Close()
	if e != nil {
		return body, e
	}
	if r.StatusCode >= 400 {
		return body, errors.New(string(body))
	}
	return body, nil
}

// DoPost is a wrapper around performing HTTP POST requests
func DoPost(c *http.Client, url string, contentType string, body io.Reader) (resp []byte, e error) {
	req, e := http.NewRequest("POST", url, body)
	if e != nil {
		return resp, e
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Authorization", "Bearer "+GetAuthToken())

	r, e := c.Do(req)
	if e != nil {
		return resp, e
	}
	resp, e = io.ReadAll(r.Body)
	r.Body.Close()
	if e != nil {
		return resp, e
	}
	if r.StatusCode >= 400 {
		return resp, errors.New(string(resp))
	}
	return resp, nil
}

// DoPostChunked is a wrapper around performing HTTP POST requests that stream chunked data
func DoPostChunked(c *http.Client, url string, contentType string, body io.Reader, onChunk func([]byte)) error {
	req, e := http.NewRequest("POST", url, body)
	if e != nil {
		return e
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Authorization", "Bearer "+GetAuthToken())

	r, e := c.Do(req)
	if e != nil {
		return e
	}
	defer r.Body.Close()

	var m int
	buf := make([]byte, 4096)
	for {
		m, e = r.Body.Read(buf)
		if m < 0 || e != nil {
			break
		}
		onChunk(buf[:m])
	}

	if r.StatusCode == 200 {
		return nil
	}
	return e
}
