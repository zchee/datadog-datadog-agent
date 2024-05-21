// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package shared

import (
	"context"

	"github.com/DataDog/datadog-agent/comp/core/pid/proto"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"
)

// GRPCClient is an implementation of KV that talks over RPC.
type GRPCClient struct {
	broker *plugin.GRPCBroker
	client proto.PIDClient
}

func (m *GRPCClient) Init(pidFilePath string, logger Logger) error {
	loggerServer := &GRPCLoggerServer{Impl: logger}

	var s *grpc.Server
	serverFunc := func(opts []grpc.ServerOption) *grpc.Server {
		s = grpc.NewServer(opts...)
		proto.RegisterLoggerServer(s, loggerServer)

		return s
	}

	brokerID := m.broker.NextId()
	go m.broker.AcceptAndServe(brokerID, serverFunc)

	_, err := m.client.Init(context.Background(), &proto.InitRequest{
		LogServer:   brokerID,
		PidFilePath: pidFilePath,
	})

	s.Stop()

	return err
}

func (m *GRPCClient) PIDFilePath() (string, error) {
	resp, err := m.client.PIDFilePath(context.Background(), &proto.Empty{})
	if err != nil {
		return "", err
	}

	return resp.Value, nil
}

// Here is the gRPC server that GRPCClient talks to.
type GRPCServer struct {
	// This is the real implementation
	Impl   Pid
	broker *plugin.GRPCBroker
}

func (m *GRPCServer) PIDFilePath(
	ctx context.Context,
	req *proto.Empty) (*proto.PIDFilePathResponse, error) {
	v, err := m.Impl.PIDFilePath()
	return &proto.PIDFilePathResponse{Value: v}, err
}

func (m *GRPCServer) Init(
	ctx context.Context,
	req *proto.InitRequest) (*proto.Empty, error) {
	conn, err := m.broker.Dial(req.LogServer)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	l := &GRPCLoggerClient{proto.NewLoggerClient(conn)}

	return &proto.Empty{}, m.Impl.Init(req.PidFilePath, l)
}

type GRPCLoggerClient struct{ client proto.LoggerClient }

func (m *GRPCLoggerClient) Log(message string) error {
	_, err := m.client.Log(context.Background(), &proto.LogRequest{
		Message: message,
	})
	if err != nil {
		hclog.Default().Info("Log", "client", err)
		return err
	}
	return err
}

// Here is the gRPC server that GRPCClient talks to.
type GRPCLoggerServer struct {
	// This is the real implementation
	Impl Logger
}

func (m *GRPCLoggerServer) Log(ctx context.Context, req *proto.LogRequest) (*proto.Empty, error) {
	err := m.Impl.Log(req.Message)
	if err != nil {
		return nil, err
	}
	return &proto.Empty{}, err
}
