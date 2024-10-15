// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

//go:build linux_bpf

package gpu

import (
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/DataDog/datadog-agent/pkg/collector/corechecks/gpu/model"
	gpuebpf "github.com/DataDog/datadog-agent/pkg/gpu/ebpf"
	"github.com/DataDog/datadog-agent/pkg/process/monitor"
	"github.com/DataDog/datadog-agent/pkg/status/health"
	"github.com/DataDog/datadog-agent/pkg/util/kernel"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

// cudaEventConsumer is responsible for consuming CUDA events from the eBPF probe, and delivering them
// to the appropriate stream handler.
type cudaEventConsumer struct {
	once    sync.Once
	closed  chan struct{}
	wg      sync.WaitGroup
	running atomic.Bool
	cfg     *Config

	mtx            sync.RWMutex
	streamHandlers map[model.StreamKey]*StreamHandler
}

// newCudaEventConsumer creates a new CUDA event consumer.
func newCudaEventConsumer(cfg *Config) *cudaEventConsumer {
	return &cudaEventConsumer{
		closed:         make(chan struct{}),
		streamHandlers: make(map[model.StreamKey]*StreamHandler),
		cfg:            cfg,
	}
}

// Stop stops the CUDA event consumer.
func (c *cudaEventConsumer) Stop() {
	if c == nil {
		return
	}
	c.once.Do(func() {
		close(c.closed)
	})
	c.wg.Wait()
}

// Start starts the CUDA event consumer.
func (c *cudaEventConsumer) Start() {
	if c == nil {
		return
	}
	health := health.RegisterLiveness("gpu-tracer-cuda-events")
	processMonitor := monitor.GetProcessMonitor()
	cleanupExit := processMonitor.SubscribeExit(c.handleProcessExit)

	c.wg.Add(1)
	go func() {
		c.running.Store(true)
		processSync := time.NewTicker(c.cfg.ScanTerminatedProcessesInterval)

		defer func() {
			cleanupExit()
			err := health.Deregister()
			if err != nil {
				log.Warnf("error de-registering health check: %s", err)
			}
			c.wg.Done()
			log.Trace("CUDA event consumer stopped")
			c.running.Store(false)
		}()

		for {
			select {
			case <-c.closed:
				return
			case <-health.C:
			case <-processSync.C:
				c.checkClosedProcesses()
			}
		}
	}()
	log.Trace("CUDA event consumer started")
}

func (c *cudaEventConsumer) getOrCreateHandler(key model.StreamKey) *StreamHandler {
	c.mtx.RLock()

	handler, ok := c.streamHandlers[key]
	if !ok {
		c.mtx.RUnlock()
		c.mtx.Lock()
		defer c.mtx.Unlock()

		handler = newStreamHandler()
		c.streamHandlers[key] = handler
	} else {
		defer c.mtx.RUnlock()
	}
	return handler
}

func (c *cudaEventConsumer) callback(data []byte) {
	dataLen := len(data)
	if dataLen < gpuebpf.SizeofCudaEventHeader {
		log.Errorf("Not enough data to parse header, data size=%d, expecting at least %d", dataLen, gpuebpf.SizeofCudaEventHeader)
		return
	}

	header := (*gpuebpf.CudaEventHeader)(unsafe.Pointer(&data[0]))

	pid := uint32(header.Pid_tgid >> 32)
	streamKey := model.StreamKey{Pid: pid, Stream: header.Stream_id}
	handler := c.getOrCreateHandler(streamKey)

	switch header.Type {
	case gpuebpf.CudaEventTypeKernelLaunch:
		if dataLen != gpuebpf.SizeofCudaKernelLaunch {
			log.Errorf("Not enough data to parse kernel launch event, data size=%d, expecting %d", dataLen, gpuebpf.SizeofCudaKernelLaunch)
			return
		}
		ckl := (*gpuebpf.CudaKernelLaunch)(unsafe.Pointer(&data[0]))
		handler.handleKernelLaunch(ckl)
	case gpuebpf.CudaEventTypeMemory:
		if dataLen != gpuebpf.SizeofCudaMemEvent {
			log.Errorf("Not enough data to parse memory event, data size=%d, expecting %d", dataLen, gpuebpf.SizeofCudaMemEvent)
			return
		}
		cme := (*gpuebpf.CudaMemEvent)(unsafe.Pointer(&data[0]))
		handler.handleMemEvent(cme)
	case gpuebpf.CudaEventTypeSync:
		if dataLen != gpuebpf.SizeofCudaSync {
			log.Errorf("Not enough data to parse sync event, data size=%d, expecting %d", dataLen, gpuebpf.SizeofCudaSync)
			return
		}
		cs := (*gpuebpf.CudaSync)(unsafe.Pointer(&data[0]))
		handler.handleSync(cs)
	}
}

func (c *cudaEventConsumer) handleProcessExit(pid uint32) {
	c.mtx.RLock()
	defer c.mtx.RUnlock()

	for key, handler := range c.streamHandlers {
		if key.Pid == pid {
			log.Debugf("Process %d ended, marking stream %d as ended", pid, key.Stream)
			// the probe is responsible for deleting the stream handler
			_ = handler.markEnd()
		}
	}
}

func (c *cudaEventConsumer) checkClosedProcesses() {
	c.mtx.RLock()
	defer c.mtx.RUnlock()

	seenPIDs := make(map[uint32]struct{})
	_ = kernel.WithAllProcs("/proc", func(pid int) error {
		seenPIDs[uint32(pid)] = struct{}{}
		return nil
	})

	for key, handler := range c.streamHandlers {
		if _, ok := seenPIDs[key.Pid]; !ok {
			log.Debugf("Process %d ended, marking stream %d as ended", key.Pid, key.Stream)
			_ = handler.markEnd()
		}
	}
}
