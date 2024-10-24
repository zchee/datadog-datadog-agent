// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package server implements a gRPC server that streams the entities stored in
// Workloadmeta.
package server

import (
	"strings"
	"sync"
	"time"

	workloadmeta "github.com/DataDog/datadog-agent/comp/core/workloadmeta/def"
	"github.com/DataDog/datadog-agent/comp/core/workloadmeta/proto"
	"github.com/DataDog/datadog-agent/comp/core/workloadmeta/telemetry"
	pb "github.com/DataDog/datadog-agent/pkg/proto/pbgo/core"
	"github.com/DataDog/datadog-agent/pkg/util/grpc"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

const (
	workloadmetaStreamSendTimeout = 1 * time.Minute
	workloadmetaKeepAliveInterval = 9 * time.Minute
	defaultResponseBufferSize     = 1000
	defaultCacheFlushInterval     = 5 * time.Second
)

// NewServer returns a new server with a workloadmeta instance
func NewServer(store workloadmeta.Component) *Server {
	return &Server{
		wmeta: store,
		cache: newCachedEvents(),
	}
}

// Server is a grpc server that streams workloadmeta entities
type Server struct {
	wmeta workloadmeta.Component
	// cache is used to store the events that are not yet sent to the client due to the stream error
	cache *cachedEvents
}

// StreamEntities streams entities from the workloadmeta store applying the given filter
func (s *Server) StreamEntities(in *pb.WorkloadmetaStreamRequest, out pb.AgentSecure_WorkloadmetaStreamEntitiesServer) error {
	filter, err := proto.WorkloadmetaFilterFromProtoFilter(in.GetFilter())
	if err != nil {
		return err
	}

	subscriber := in.GetRequestId()
	if subscriber == "" {
		subscriber = "stream-client"
	}

	workloadmetaEventsChannel := s.wmeta.Subscribe(subscriber, workloadmeta.NormalPriority, filter)
	defer s.wmeta.Unsubscribe(workloadmetaEventsChannel)

	ticker := time.NewTicker(workloadmetaKeepAliveInterval)
	defer ticker.Stop()

	responses := make(chan *pb.WorkloadmetaStreamResponse, defaultResponseBufferSize)
	errChan := make(chan error)
	stopCh := make(chan struct{})
	useCache := supportsCachedEvent(subscriber)

	// async send to avoid blocking the stream which could make health checks fail on workloadmeta
	go asyncSend(subscriber, out, errChan, responses, useCache, s.cache)

	// start the cache if the subscriber supports it
	if useCache {
		go s.cache.start(subscriber, out, errChan, stopCh)
	}

	for {
		select {
		case eventBundle, ok := <-workloadmetaEventsChannel:
			if !ok {
				return nil
			}
			eventBundle.Acknowledge()

			protobufEvents := make([]*pb.WorkloadmetaEvent, 0, len(eventBundle.Events))

			for _, event := range eventBundle.Events {
				protobufEvent, err := proto.ProtobufEventFromWorkloadmetaEvent(event)

				if err != nil {
					log.Errorf("error converting workloadmeta event to protobuf: %s", err)
					continue
				}

				if protobufEvent != nil {
					protobufEvents = append(protobufEvents, protobufEvent)
				}
			}

			if len(protobufEvents) > 0 {
				responses <- &pb.WorkloadmetaStreamResponse{
					Events: protobufEvents,
				}
			}
			ticker.Reset(workloadmetaKeepAliveInterval)
		case <-out.Context().Done():
			stopCh <- struct{}{}
			close(responses)
			return nil

		// The remote workloadmeta client has a timeout that closes the
		// connection after some minutes of inactivity. In order to avoid
		// closing the connection and having to open it again, the server will
		// send an empty message from time to time as defined in the ticker. The
		// goal is only to keep the connection alive without losing the
		// protection against “half” closed connections brought by the timeout.
		case <-ticker.C:
			responses <- &pb.WorkloadmetaStreamResponse{
				Events: []*pb.WorkloadmetaEvent{},
			}
		case e := <-errChan:
			stopCh <- struct{}{}
			close(responses)
			return e
		}
	}
}

func asyncSend(subscriber string, out pb.AgentSecure_WorkloadmetaStreamEntitiesServer, errChan chan error, responses chan *pb.WorkloadmetaStreamResponse, useCache bool, cache *cachedEvents) {
	for resp := range responses {
		if err := sendResponse(out, resp); err != nil {
			// cache the events that were not sent
			if useCache && len(resp.Events) > 0 {
				cache.add(subscriber, resp.Events)
			}

			errChan <- err
			return
		}
	}
}

func sendResponse(out pb.AgentSecure_WorkloadmetaStreamEntitiesServer, response *pb.WorkloadmetaStreamResponse) error {
	err := grpc.DoWithTimeout(func() error {
		return out.Send(response)
	}, workloadmetaStreamSendTimeout)

	if err != nil {
		log.Warnf("error sending workloadmeta event(size=%d): %s", len(response.Events), err)
		telemetry.RemoteServerErrors.Inc()
		return err
	}
	return nil
}

type cachedEvents struct {
	sync.Mutex
	events map[string][]*pb.WorkloadmetaEvent
}

func newCachedEvents() *cachedEvents {
	return &cachedEvents{
		events: make(map[string][]*pb.WorkloadmetaEvent),
	}
}

func (c *cachedEvents) add(subscriber string, events []*pb.WorkloadmetaEvent) {
	c.Lock()
	if c.events[subscriber] == nil {
		c.events[subscriber] = []*pb.WorkloadmetaEvent{}
	}
	c.events[subscriber] = append(c.events[subscriber], events...)
	c.Unlock()
}

func (c *cachedEvents) start(subscriber string, out pb.AgentSecure_WorkloadmetaStreamEntitiesServer, errChan chan error, stopCh chan struct{}) {
	log.Infof("starting cache for subscriber %s", subscriber)
	ticker := time.NewTicker(defaultCacheFlushInterval)
	defer ticker.Stop()

	if c.events[subscriber] == nil {
		c.events[subscriber] = []*pb.WorkloadmetaEvent{}
	}

	for {
		select {
		case <-ticker.C:
			if len(c.events[subscriber]) == 0 {
				continue
			}

			if err := sendResponse(out, &pb.WorkloadmetaStreamResponse{
				Events: c.events[subscriber],
			}); err != nil {
				errChan <- err
				return
			}
			c.Lock()
			c.events[subscriber] = c.events[subscriber][:0]
			c.Unlock()
		case <-stopCh:
			return
		}
	}
}

func supportsCachedEvent(subscriber string) bool {
	// currently only support terminated pod subscribers
	return strings.Index(subscriber, workloadmeta.TerminatedPod) == 0
}
