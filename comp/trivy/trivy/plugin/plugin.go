//go:build trivy

package main

import (
	"github.com/DataDog/datadog-agent/comp/trivy/trivy"
	"github.com/DataDog/datadog-agent/comp/trivy/trivy/trivyimpl"
)

// go build -tags "bundle_agent datadog.no_waf containerd etcd docker trivy cri apm consul bundle_security_agent kubeapiserver netcgo zstd fargateprocess python bundle_trace_agent jetson zk jmx ec2 systemd process kubelet otlp bundle_process_agent podman oracle orchestrator zlib gce" -buildmode=plugin

func GetComponent() trivy.Component {
	return trivyimpl.NewTrivy()
}
