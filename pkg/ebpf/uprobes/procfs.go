// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

//go:build linux

package uprobes

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const procFSUpdateTimeout = 100 * time.Millisecond

// ProcInfo holds the information extracted from procfs, to avoid repeat calls to the filesystem.
type ProcInfo struct {
	procRoot string
	PID      uint32
	exe      string
	comm     string
}

// NewProcInfo creates a new ProcInfo object.
func NewProcInfo(procRoot string, pid uint32) *ProcInfo {
	return &ProcInfo{
		procRoot: procRoot,
		PID:      pid,
	}
}

// Avoid allocations, reuse the error to mark "iteration start" in the loop
var errIterStart = errors.New("iteration start")

const pfKthread = 0x00200000

func isKernelThread(p *ProcInfo) bool {
	pidAsStr := strconv.FormatUint(uint64(p.PID), 10)
	filePath := filepath.Join(p.procRoot, pidAsStr, "stat")

	content, err := os.ReadFile(filePath)
	if err != nil {
		return false
	}

	startIndex := bytes.LastIndexByte(content, byte(')'))
	if startIndex == -1 || startIndex+1 >= len(content) {
		return false
	}

	fields := strings.Fields(string(content[startIndex+1:]))
	if len(fields) < 50 {
		return false
	}

	flagsRaw := fields[8-2]
	flags, err := strconv.ParseUint(flagsRaw, 10, 64)
	if err != nil {
		return false
	}

	return flags&pfKthread == pfKthread
}

func waitUntilSucceeds[T any](p *ProcInfo, procFile string, readFunc func(string) (T, error)) (T, error) {
	// Read the exe link
	pidAsStr := strconv.FormatUint(uint64(p.PID), 10)
	filePath := filepath.Join(p.procRoot, pidAsStr, procFile)

	var result T
	err := errIterStart
	end := time.Now().Add(procFSUpdateTimeout)

	checkedKernelThread := false

	for err != nil && end.After(time.Now()) {
		result, err = readFunc(filePath)
		if err == nil {
			break
		}

		if !checkedKernelThread {
			checkedKernelThread = true
			if isKernelThread(p) {
				break
			}
		}

		time.Sleep(10 * time.Millisecond)
	}

	return result, err
}

// Exe returns the path to the executable of the process.
func (p *ProcInfo) Exe() (string, error) {
	var err error
	if p.exe == "" {
		p.exe, err = waitUntilSucceeds(p, "exe", os.Readlink)
		if err != nil {
			return "", err
		}
	}

	if p.exe == "" {
		return "", errors.New("exe link is empty")
	}

	return p.exe, nil
}

const (
	// Defined in https://man7.org/linux/man-pages/man5/proc.5.html.
	taskCommLen = 16
)

var (
	taskCommLenBufferPool = sync.Pool{
		New: func() any {
			buf := make([]byte, taskCommLen)
			return &buf
		},
	}
)

func (p *ProcInfo) readComm(commFile string) (string, error) {
	file, err := os.Open(commFile)
	if err != nil {
		return "", err
	}
	defer file.Close()

	buf := taskCommLenBufferPool.Get().(*[]byte)
	defer taskCommLenBufferPool.Put(buf)
	n, err := file.Read(*buf)
	if err != nil {
		// short living process can hit here, or slow start of another process.
		return "", nil
	}
	return string(bytes.TrimSpace((*buf)[:n])), nil
}

// Comm returns the command name of the process.
func (p *ProcInfo) Comm() (string, error) {
	var err error
	if p.comm == "" {
		p.comm, err = waitUntilSucceeds(p, "comm", p.readComm)
		if err != nil {
			return "", err
		}
	}

	return p.comm, nil
}
