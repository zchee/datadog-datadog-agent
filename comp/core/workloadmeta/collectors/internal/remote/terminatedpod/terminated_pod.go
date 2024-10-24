// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build kubelet

// Package terminatedpod implements the remote terminatedpod Collector.
package terminatedpod

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"go.uber.org/fx"
	"google.golang.org/grpc"
	"google.golang.org/grpc/grpclog"

	"github.com/DataDog/datadog-agent/comp/core/workloadmeta/collectors/internal/remote"
	workloadmeta "github.com/DataDog/datadog-agent/comp/core/workloadmeta/def"
	"github.com/DataDog/datadog-agent/comp/core/workloadmeta/proto"
	"github.com/DataDog/datadog-agent/pkg/api/security"
	"github.com/DataDog/datadog-agent/pkg/config/model"
	pkgconfigsetup "github.com/DataDog/datadog-agent/pkg/config/setup"
	pb "github.com/DataDog/datadog-agent/pkg/proto/pbgo/core"
	"github.com/DataDog/datadog-agent/pkg/util/clusteragent"
	"github.com/DataDog/datadog-agent/pkg/util/flavor"
	grpcutil "github.com/DataDog/datadog-agent/pkg/util/grpc"
	"github.com/DataDog/datadog-agent/pkg/util/kubernetes/kubelet"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

type client struct {
	cl       pb.AgentSecureClient
	filter   *workloadmeta.Filter
	nodeName string
}

func (c *client) StreamEntities(ctx context.Context) (remote.Stream, error) {
	protoFilter, err := proto.ProtobufFilterFromWorkloadmetaFilter(c.filter)
	if err != nil {
		return nil, err
	}

	// set pre-registered filter id as filter func can't be sent over gRPC
	protoFilter.PreRegisteredFilterId = int32(workloadmeta.TerminatedPodFilter)
	protoFilter.FilterFuncParams = []string{c.nodeName}

	streamcl, err := c.cl.WorkloadmetaStreamEntities(
		ctx,
		&pb.WorkloadmetaStreamRequest{
			Filter:    protoFilter,
			RequestId: fmt.Sprintf("%s-%s", workloadmeta.TerminatedPod, c.nodeName),
		},
	)
	if err != nil {
		return nil, err
	}
	return &stream{cl: streamcl}, nil
}

type stream struct {
	cl pb.AgentSecure_WorkloadmetaStreamEntitiesClient
}

func (s *stream) Recv() (interface{}, error) {
	return s.cl.Recv()
}

type streamHandler struct {
	endpoint string
	port     int
	filter   *workloadmeta.Filter
	model.Config
}

// NewCollector returns a CollectorProvider to build a remote workloadmeta collector, and an error if any.
func NewCollector() (workloadmeta.CollectorProvider, error) {
	endpoint, port, err := getClusterAgentEndpoint()
	if err != nil {
		log.Error("unable to get cluster agent endpoint: ", err)
	}
	log.Infof("remote-terminated-pod collector is targeting %s:%d", endpoint, port)

	return workloadmeta.CollectorProvider{
		Collector: &remote.GenericCollector{
			CollectorID: workloadmeta.TerminatedPod,
			StreamHandler: &streamHandler{
				endpoint: endpoint,
				port:     port,
				// filter is set on the server side as filter func can't be sent over gRPC
				filter: workloadmeta.NewFilterBuilder().
					AddKind(workloadmeta.KindKubernetesPod).
					SetSource(workloadmeta.SourceKubeAPISever).
					SetEventType(workloadmeta.EventTypeUnset).
					Build(),
				Config: pkgconfigsetup.Datadog(),
			},
			Catalog: workloadmeta.NodeAgent,
		},
	}, nil
}

// GetFxOptions returns the FX framework options for the collector
func GetFxOptions() fx.Option {
	return fx.Provide(NewCollector)
}

func init() {
	// TODO(components): verify the grpclogin is initialized elsewhere and cleanup
	grpclog.SetLoggerV2(grpcutil.NewLogger())
}

func (s *streamHandler) Endpoint() string {
	if s.endpoint == "" {
		s.setClusterAgentEndpoint()
	}
	return s.endpoint
}

func (s *streamHandler) Port() int {
	if s.port == 0 {
		s.setClusterAgentEndpoint()
	}
	return s.port
}

func (s *streamHandler) TokenFetcher() (string, error) {
	return security.GetClusterAgentAuthToken(pkgconfigsetup.Datadog())
}

func (s *streamHandler) NewClient(cc grpc.ClientConnInterface) remote.GrpcClient {
	var nodeName string
	if kubeUtil, err := kubelet.GetKubeUtil(); err == nil && kubeUtil != nil {
		nodeName, err = kubeUtil.GetNodename(context.Background())
		if err != nil {
			log.Error("unable to get node name: ", err)
		}
	} else {
		log.Error("unable to get kubelet util: ", err)
	}

	log.Infof("remote-terminated-pod collector is targeting node %s", nodeName)

	return &client{
		cl:       pb.NewAgentSecureClient(cc),
		filter:   s.filter,
		nodeName: nodeName,
	}
}

// IsEnabled returns if the feature is enabled
// This collector is enabled only for node agents
func (s *streamHandler) IsEnabled() bool {
	return pkgconfigsetup.Datadog().GetBool("orchestrator_explorer.terminated_resources.enabled") &&
		flavor.GetFlavor() == flavor.DefaultAgent &&
		!pkgconfigsetup.IsCLCRunner(pkgconfigsetup.Datadog())
}

func (s *streamHandler) HandleResponse(_ workloadmeta.Component, resp interface{}) ([]workloadmeta.CollectorEvent, error) {
	response, ok := resp.(*pb.WorkloadmetaStreamResponse)
	if !ok {
		return nil, fmt.Errorf("incorrect response type")
	}
	var collectorEvents []workloadmeta.CollectorEvent

	for _, protoEvent := range response.Events {
		workloadmetaEvent, err := proto.WorkloadmetaEventFromProtoEvent(protoEvent)
		if err != nil {
			return nil, err
		}

		collectorEvent := workloadmeta.CollectorEvent{
			Type:   workloadmetaEvent.Type,
			Source: workloadmeta.SourceRemoteTerminatedPodCollector,
			Entity: workloadmetaEvent.Entity,
		}
		log.Info("remote terminated pod collector received event: ", workloadmetaEvent.Entity.(*workloadmeta.KubernetesPod).Name)

		collectorEvents = append(collectorEvents, collectorEvent)
	}

	return collectorEvents, nil
}

func (s *streamHandler) HandleResync(store workloadmeta.Component, events []workloadmeta.CollectorEvent) {
	entities := make([]workloadmeta.Entity, 0, len(events))
	for _, event := range events {
		entities = append(entities, event.Entity)
	}
	// This should be the first response that we got from workloadmeta after
	// we lost the connection and specified that a re-sync is needed. So, at
	// this point we know that "entities" contains all the existing entities
	// in the store, because when a client subscribes to workloadmeta, the
	// first response is always a bundle of events with all the existing
	// entities in the store that match the filters specified (see
	// workloadmeta.Store#Subscribe).
	store.Reset(entities, workloadmeta.SourceRemoteTerminatedPodCollector)
}

func (s *streamHandler) setClusterAgentEndpoint() {
	endpoint, port, err := getClusterAgentEndpoint()
	if err != nil {
		log.Error("unable to get cluster agent endpoint: ", err)
	}
	s.endpoint = endpoint
	s.port = port
}

func getClusterAgentEndpoint() (string, int, error) {
	target, err := clusteragent.GetClusterAgentEndpoint()
	if err != nil {
		return "", 0, err
	}

	target = strings.TrimPrefix(target, "https://")

	endpointPort := strings.Split(target, ":")
	port, err := strconv.Atoi(endpointPort[len(endpointPort)-1])
	if err != nil {
		return "", 0, err
	}

	return endpointPort[0], port, nil
}
