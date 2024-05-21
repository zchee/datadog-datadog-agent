// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package shared

import (
	"context"

	"github.com/DataDog/datadog-agent/comp/core/pid/proto"
)

// GRPCClient is an implementation of KV that talks over RPC.
type GRPCClient struct{ client proto.PIDClient }

func (m *GRPCClient) Init(pidFilePath string) error {
	_, err := m.client.Init(context.Background(), &proto.InitRequest{
		PidFilePath: pidFilePath,
	})
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
	Impl Pid
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
	return &proto.Empty{}, m.Impl.Init(req.PidFilePath)
}
