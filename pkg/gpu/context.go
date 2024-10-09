// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf

package gpu

import (
	"debug/elf"
	"fmt"
	"slices"
	"time"

	"github.com/DataDog/datadog-agent/pkg/gpu/cuda"
	"github.com/DataDog/datadog-agent/pkg/network/events"
	"github.com/DataDog/datadog-agent/pkg/network/tracer"
	sectime "github.com/DataDog/datadog-agent/pkg/security/resolvers/time"
	"github.com/DataDog/datadog-agent/pkg/util/kernel"
)

// systemContext holds certain attributes about the system that are used by the GPU probe.
type systemContext struct {
	// procRoot is the root directory for the proc filesystem
	procRoot string

	// deviceSmVersions maps each device index to its SM (Compute architecture) version
	deviceSmVersions map[int]int

	// fileData maps each file path to its Fatbin file data
	fileData map[string]*fileData

	// pidMaps maps each process ID to its memory maps
	pidMaps map[int]*kernel.ProcMapEntries

	// timeResolver is used to convert from kernel time to system time
	timeResolver *sectime.Resolver

	// processCache is used to resolve process information
	processCache *tracer.ProcessCache

	// selectedDeviceByPIDAndTID maps each process ID to the map of thread IDs to selected device index.
	// The reason to have a nested map is to allow easy cleanup of data when a process exits.
	// The thread ID is important as the device selection in CUDA is per-thread.
	// Note that this is the device index as seen by the process itself, which might
	// be modified by the CUDA_VISIBLE_DEVICES environment variable later
	selectedDeviceByPIDAndTID map[int]map[int]int32

	// gpuDevices is the list of GPU devices on the system
	gpuDevices []cuda.GpuDevice

	// visibleDevicesCache is a cache of visible devices for each process, to avoid
	// looking into the environment variables every time
	visibleDevicesCache map[int][]cuda.GpuDevice
}

// fileData holds the symbol table and Fatbin data for a given file.
type fileData struct {
	symbolTable  map[uint64]string
	fatbin       *cuda.Fatbin
	lastAccessed time.Time
}

func (fd *fileData) updateAccessTime() {
	fd.lastAccessed = time.Now()
}

type systemContextOpts string

const (
	// systemContextOptDisableGpuQuery disables querying GPU devices, useful for tests where no GPU is available
	systemContextOptDisableGpuQuery systemContextOpts = "disableGpuQuery"
)

func getSystemContext(procRoot string, opts ...systemContextOpts) (*systemContext, error) {
	var err error

	ctx := &systemContext{
		fileData:                  make(map[string]*fileData),
		pidMaps:                   make(map[int]*kernel.ProcMapEntries),
		selectedDeviceByPIDAndTID: make(map[int]map[int]int32),
		procRoot:                  procRoot,
		visibleDevicesCache:       make(map[int][]cuda.GpuDevice),
	}

	if !slices.Contains(opts, systemContextOptDisableGpuQuery) {
		if err = ctx.queryDevices(); err != nil {
			return nil, fmt.Errorf("error querying devices: %w", err)
		}
	}

	ctx.timeResolver, err = sectime.NewResolver()
	if err != nil {
		return nil, fmt.Errorf("cannot create time resolver: %w", err)
	}

	ctx.processCache, err = tracer.NewProcessCache(32768)
	if err != nil {
		return nil, fmt.Errorf("cannot create process cache: %w", err)
	}

	if err = events.Init(); err != nil {
		return nil, fmt.Errorf("cannot init events system: %w", err)
	}

	events.RegisterHandler(ctx.processCache)

	return ctx, nil
}

func (ctx *systemContext) queryDevices() error {
	var err error
	ctx.gpuDevices, err = cuda.GetGPUDevices()
	if err != nil {
		return fmt.Errorf("error getting GPU devices: %w", err)
	}

	ctx.deviceSmVersions = make(map[int]int)
	for i, device := range ctx.gpuDevices {
		major, minor, ret := device.GetCudaComputeCapability()
		if err = cuda.WrapNvmlError(ret); err != nil {
			return fmt.Errorf("error getting SM version: %w", err)
		}
		ctx.deviceSmVersions[i] = major*10 + minor
	}

	return nil
}

func (ctx *systemContext) getFileData(path string) (*fileData, error) {
	if fd, ok := ctx.fileData[path]; ok {
		fd.updateAccessTime()
		return fd, nil
	}

	elfFile, err := elf.Open(path)
	if err != nil {
		return nil, fmt.Errorf("error opening ELF file %s: %w", path, err)
	}

	fatbin, err := cuda.ParseFatbinFromELFFile(elfFile)
	if err != nil {
		return nil, fmt.Errorf("error parsing fatbin on %s: %w", path, err)
	}

	fd := &fileData{
		symbolTable: make(map[uint64]string),
		fatbin:      fatbin,
	}

	syms, err := elfFile.Symbols()
	if err != nil {
		return nil, fmt.Errorf("error reading symbols from ELF file %s: %w", path, err)
	}

	for _, sym := range syms {
		fd.symbolTable[sym.Value] = sym.Name
	}

	fd.updateAccessTime()
	ctx.fileData[path] = fd
	return ctx.fileData[path], nil
}

func (ctx *systemContext) getProcessMemoryMaps(pid int) (*kernel.ProcMapEntries, error) {
	if maps, ok := ctx.pidMaps[pid]; ok {
		return maps, nil
	}

	maps, err := kernel.ReadProcessMemMaps(pid, "/proc")
	if err != nil {
		return nil, fmt.Errorf("error reading process memory maps: %w", err)
	}

	ctx.pidMaps[pid] = &maps
	return &maps, nil
}

func (ctx *systemContext) cleanupDataForProcess(pid int) {
	delete(ctx.pidMaps, pid)
}

func (ctx *systemContext) cleanupOldEntries() {
	maxFatbinAge := 5 * time.Minute
	fatbinExpirationTime := time.Now().Add(-maxFatbinAge)

	for path, fd := range ctx.fileData {
		if fd.lastAccessed.Before(fatbinExpirationTime) {
			delete(ctx.fileData, path)
		}
	}
}

func (ctx *systemContext) getCurrentActiveGpuDevice(pid int, tid int) (*cuda.GpuDevice, error) {
	visibleDevices, ok := ctx.visibleDevicesCache[pid]
	if !ok {
		visibleDevices, err := cuda.GetVisibleDevicesForProcess(ctx.gpuDevices, pid, ctx.procRoot)
		if err != nil {
			return nil, fmt.Errorf("error getting visible devices for process %d: %w", pid, err)
		}

		ctx.visibleDevicesCache[pid] = visibleDevices
	}

	if len(visibleDevices) == 0 {
		return nil, fmt.Errorf("no GPU devices for process %d", pid)
	}

	selectedDeviceIndex := int32(0)
	pidMap, ok := ctx.selectedDeviceByPIDAndTID[pid]
	if ok {
		selectedDeviceIndex = pidMap[tid] // Defaults to 0, which is the same as CUDA
	}

	if selectedDeviceIndex < 0 || selectedDeviceIndex >= int32(len(visibleDevices)) {
		return nil, fmt.Errorf("device index %d is out of range", selectedDeviceIndex)
	}

	return &visibleDevices[selectedDeviceIndex], nil
}

func (ctx *systemContext) setDeviceSelection(pid int, tid int, deviceIndex int32) {
	if _, ok := ctx.selectedDeviceByPIDAndTID[pid]; !ok {
		ctx.selectedDeviceByPIDAndTID[pid] = make(map[int]int32)
	}

	ctx.selectedDeviceByPIDAndTID[pid][tid] = deviceIndex
}
