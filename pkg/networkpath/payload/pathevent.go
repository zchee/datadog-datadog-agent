// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

// Package payload contains Network Path payload
package payload

import "github.com/DataDog/datadog-agent/pkg/network"

// Protocol defines supported network protocols
// Please define new protocols based on the Keyword from:
// https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
type Protocol string

const (
	// ProtocolTCP is the TCP protocol.
	ProtocolTCP Protocol = "TCP"
	// ProtocolUDP is the UDP protocol.
	ProtocolUDP Protocol = "UDP"
)

// PathOrigin origin of the path e.g. network_traffic, network_path_integration
type PathOrigin string

const (
	// PathOriginNetworkTraffic correspond to traffic from network traffic (NPM).
	PathOriginNetworkTraffic PathOrigin = "network_traffic"
	// PathOriginNetworkPathIntegration correspond to traffic from network_path integration.
	PathOriginNetworkPathIntegration PathOrigin = "network_path_integration"
)

// NetworkPathHop encapsulates the data for a single
// hop within a path
type NetworkPathHop struct {
	TTL       int    `json:"ttl"`
	IPAddress string `json:"ip_address"`

	// hostname is the reverse DNS of the ip_address
	// TODO (separate PR): we might want to rename it to reverse_dns_hostname for consistency with destination.reverse_dns_hostname
	Hostname string `json:"hostname,omitempty"`

	RTT       float64 `json:"rtt,omitempty"`
	Reachable bool    `json:"reachable"`
}

// NetworkPathSource encapsulates information
// about the source of a path
type NetworkPathSource struct {
	Hostname    string       `json:"hostname"`
	Via         *network.Via `json:"via,omitempty"`
	NetworkID   string       `json:"network_id,omitempty"` // Today this will be a VPC ID since we only resolve AWS resources
	Service     string       `json:"service,omitempty"`
	ContainerID string       `json:"container_id,omitempty"`
}

// NetworkPathDestination encapsulates information
// about the destination of a path
type NetworkPathDestination struct {
	Hostname           string `json:"hostname"`
	IPAddress          string `json:"ip_address"`
	Port               uint16 `json:"port"`
	Service            string `json:"service,omitempty"`
	ReverseDNSHostname string `json:"reverse_dns_hostname,omitempty"`
}

// NetworkPath encapsulates data that defines a
// path between two hosts as mapped by the agent
type NetworkPath struct {
	Timestamp    int64                  `json:"timestamp"`
	AgentVersion string                 `json:"agent_version"`
	Namespace    string                 `json:"namespace"` // namespace used to resolve NDM resources
	PathtraceID  string                 `json:"pathtrace_id"`
	Origin       PathOrigin             `json:"origin"`
	Protocol     Protocol               `json:"protocol"`
	Source       NetworkPathSource      `json:"source"`
	Destination  NetworkPathDestination `json:"destination"`
	Hops         []NetworkPathHop       `json:"hops"`
	Tags         []string               `json:"tags,omitempty"`
}
