// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.
//go:build kubelet && orchestrator

// Package pod is used for the orchestrator pod check
package pod

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"go.uber.org/atomic"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/informers"
	v1pod "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/tools/cache"

	model "github.com/DataDog/agent-payload/v5/process"
	"github.com/DataDog/datadog-agent/comp/core/autodiscovery/integration"
	"github.com/DataDog/datadog-agent/pkg/aggregator/sender"
	"github.com/DataDog/datadog-agent/pkg/collector/check"
	core "github.com/DataDog/datadog-agent/pkg/collector/corechecks"
	"github.com/DataDog/datadog-agent/pkg/collector/corechecks/cluster/orchestrator/processors"
	k8sProcessors "github.com/DataDog/datadog-agent/pkg/collector/corechecks/cluster/orchestrator/processors/k8s"
	pkgconfigsetup "github.com/DataDog/datadog-agent/pkg/config/setup"
	"github.com/DataDog/datadog-agent/pkg/orchestrator"
	oconfig "github.com/DataDog/datadog-agent/pkg/orchestrator/config"
	"github.com/DataDog/datadog-agent/pkg/process/checks"
	"github.com/DataDog/datadog-agent/pkg/util/hostname"
	"github.com/DataDog/datadog-agent/pkg/util/kubernetes/apiserver"
	"github.com/DataDog/datadog-agent/pkg/util/kubernetes/clustername"
	"github.com/DataDog/datadog-agent/pkg/util/kubernetes/kubelet"
	"github.com/DataDog/datadog-agent/pkg/util/log"
	"github.com/DataDog/datadog-agent/pkg/util/optional"
)

// CheckName is the name of the check
const CheckName = "orchestrator_pod"

var groupID atomic.Int32
var startTerminatedPodsCollection sync.Once

func nextGroupID() int32 {
	groupID.Add(1)
	return groupID.Load()
}

// Check doesn't need additional fields
type Check struct {
	core.CheckBase
	hostName                     string
	clusterID                    string
	sender                       sender.Sender
	processor                    *processors.Processor
	config                       *oconfig.OrchestratorConfig
	systemInfo                   *model.SystemInfo
	stopTerminatedPodsCollection chan struct{}
}

// Factory creates a new check factory
func Factory() optional.Option[func() check.Check] {
	return optional.NewOption(newCheck)
}

func newCheck() check.Check {
	return &Check{
		CheckBase: core.NewCheckBase(CheckName),
		config:    oconfig.NewDefaultOrchestratorConfig(),
	}
}

// Configure the CPU check
// nil check to allow for overrides
func (c *Check) Configure(
	senderManager sender.SenderManager,
	integrationConfigDigest uint64,
	data integration.Data,
	initConfig integration.Data,
	source string,
) error {
	c.BuildID(integrationConfigDigest, data, initConfig)

	err := c.CommonConfigure(senderManager, initConfig, data, source)
	if err != nil {
		return err
	}

	err = c.config.Load()
	if err != nil {
		return err
	}
	if !c.config.OrchestrationCollectionEnabled {
		log.Warn("orchestrator pod check is configured but the feature is disabled")
		return nil
	}
	if c.config.KubeClusterName == "" {
		return errors.New("orchestrator check is configured but the cluster name is empty")
	}

	if c.processor == nil {
		c.processor = processors.NewProcessor(new(k8sProcessors.PodHandlers))
	}

	if c.sender == nil {
		sender, err := c.GetSender()
		if err != nil {
			return err
		}
		c.sender = sender
	}

	if c.hostName == "" {
		hname, _ := hostname.Get(context.TODO())
		c.hostName = hname
	}

	c.systemInfo, err = checks.CollectSystemInfo()
	if err != nil {
		log.Warnf("Failed to collect system info: %s", err)
	}

	c.stopTerminatedPodsCollection = make(chan struct{})

	return nil
}

// Run executes the check
func (c *Check) Run() error {
	if pkgconfigsetup.Datadog().GetBool("orchestrator_explorer.terminated_resources") {
		startTerminatedPodsCollection.Do(func() {
			log.Infof("Starting terminated pods collection")
			if err := c.startTerminatedPodsCollection(); err != nil {
				log.Errorf("Unable to start terminated pods collection: %s", err)
			}
		})
	}

	if c.clusterID == "" {
		clusterID, err := clustername.GetClusterID()
		if err != nil {
			return err
		}
		c.clusterID = clusterID
	}

	kubeUtil, err := kubelet.GetKubeUtil()
	if err != nil {
		return err
	}

	podList, err := kubeUtil.GetRawLocalPodList(context.TODO())
	if err != nil {
		return err
	}

	groupID := nextGroupID()
	ctx := &processors.K8sProcessorContext{
		BaseProcessorContext: processors.BaseProcessorContext{
			Cfg:              c.config,
			MsgGroupID:       groupID,
			NodeType:         orchestrator.K8sPod,
			ClusterID:        c.clusterID,
			ManifestProducer: true,
		},
		HostName:           c.hostName,
		ApiGroupVersionTag: "kube_api_version:v1",
		SystemInfo:         c.systemInfo,
	}

	processResult, processed := c.processor.Process(ctx, podList)
	if processed == -1 {
		return fmt.Errorf("unable to process pods: a panic occurred")
	}

	orchestrator.SetCacheStats(len(podList), processed, ctx.NodeType)

	c.sender.OrchestratorMetadata(processResult.MetadataMessages, c.clusterID, int(orchestrator.K8sPod))
	c.sender.OrchestratorManifest(processResult.ManifestMessages, c.clusterID)

	return nil
}

func (c *Check) startTerminatedPodsCollection() error {
	podInformer, err := getPodInformer()
	if err != nil {
		return err
	}

	if _, err = podInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		DeleteFunc: c.deletionHandler,
	}); err != nil {
		return err
	}

	go podInformer.Informer().Run(c.stopTerminatedPodsCollection)

	return nil
}

func (c *Check) deletionHandler(obj interface{}) {
	pod, ok := obj.(*v1.Pod)
	if !ok {
		log.Warn("deletionHandler received an object that is not a Pod")
		return
	}

	ctx := &processors.K8sProcessorContext{
		BaseProcessorContext: processors.BaseProcessorContext{
			Cfg:              c.config,
			NodeType:         orchestrator.K8sPod,
			ClusterID:        c.clusterID,
			ManifestProducer: true,
		},
		HostName:           c.hostName,
		ApiGroupVersionTag: "kube_api_version:v1",
		SystemInfo:         c.systemInfo,
	}

	processResult, processed := c.processor.Process(ctx, []*v1.Pod{pod})
	if processed == -1 {
		log.Warn("unable to process pods: a panic occurred")
		return
	}

	orchestrator.SetCacheStats(1, processed, ctx.NodeType)

	c.sender.OrchestratorMetadata(processResult.MetadataMessages, c.clusterID, int(orchestrator.K8sPod))
	c.sender.OrchestratorManifest(processResult.ManifestMessages, c.clusterID)
}

func getPodInformer() (v1pod.PodInformer, error) {
	kubeUtil, err := kubelet.GetKubeUtil()
	if err != nil {
		return nil, err
	}

	nodeName, err := kubeUtil.GetNodename(context.Background())
	if err != nil {
		return nil, err
	}

	apiCtx, apiCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer apiCancel()

	apiClient, err := apiserver.WaitForAPIClient(apiCtx)
	if err != nil {
		return nil, err
	}

	tweakListOptions := func(options *metav1.ListOptions) {
		options.FieldSelector = fields.OneTermEqualSelector("spec.nodeName", nodeName).String()
	}

	informerFactory := informers.NewSharedInformerFactoryWithOptions(apiClient.InformerCl, 300*time.Second, informers.WithTweakListOptions(tweakListOptions))

	return informerFactory.Core().V1().Pods(), nil
}

// Stop stops the check
func (c *Check) Stop() {
	close(c.stopTerminatedPodsCollection)
	log.Infof("Terminated pods collection stopped")
}
