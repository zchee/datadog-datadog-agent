// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux

// Package processresolver holds processresolver related files
package processresolver

import (
	"testing"
	"time"

	processlist "github.com/DataDog/datadog-agent/pkg/security/process_list"
	cgroupModel "github.com/DataDog/datadog-agent/pkg/security/resolvers/cgroup/model"
	"github.com/DataDog/datadog-agent/pkg/security/secl/model"
	"github.com/stretchr/testify/assert"
	"golang.org/x/exp/slices"
)

func newFakeExecEvent(ppid, pid int, pathname string) *model.Event {
	e := model.NewFakeEvent()
	e.Type = uint32(model.ExecEventType)
	e.ProcessContext = &model.ProcessContext{}
	e.ProcessContext.PPid = uint32(ppid)
	e.ProcessContext.Pid = uint32(pid)
	e.ProcessContext.ForkTime = time.Now()
	e.ProcessContext.FileEvent.PathnameStr = pathname
	return e
}

type testStats struct {
	TotalProcessNodes   int64
	TotalExecNodes      int64
	CurrentProcessNodes int64
	CurrentExecNodes    int64
}

func (ts *testStats) AddProcess(nbTreads int64) {
	ts.TotalProcessNodes++
	ts.TotalExecNodes += nbTreads
	ts.CurrentProcessNodes++
	ts.CurrentExecNodes += nbTreads
}

func (ts *testStats) AddExec() {
	ts.TotalExecNodes++
	ts.CurrentExecNodes++
}

func (ts *testStats) DeleteProcess(nbThreads int64) {
	ts.CurrentProcessNodes--
	ts.CurrentExecNodes -= nbThreads
}

func (ts *testStats) ValidateCounters(t *testing.T, pl *processlist.ProcessList) {
	assert.Equal(t, ts.TotalProcessNodes, pl.Stats.TotalProcessNodes)
	assert.Equal(t, ts.TotalExecNodes, pl.Stats.TotalExecNodes)
	assert.Equal(t, ts.CurrentProcessNodes, pl.Stats.CurrentProcessNodes)
	assert.Equal(t, ts.CurrentExecNodes, pl.Stats.CurrentExecNodes)
	assert.Equal(t, int(ts.CurrentProcessNodes), pl.GetProcessCacheSize())
	assert.Equal(t, int(ts.CurrentExecNodes), pl.GetExecCacheSize())
}

func checkParentality(pl *processlist.ProcessList, pc *ProcessResolver, parent, child *model.Event) bool {
	// first, get cached processes
	cachedProcessParent := pl.GetCacheProcess(pc.GetProcessCacheKey(&parent.ProcessContext.Process))
	cachedProcessChild := pl.GetCacheProcess(pc.GetProcessCacheKey(&child.ProcessContext.Process))
	if cachedProcessParent == nil || cachedProcessChild == nil {
		return false
	}
	// then, ensure child is part of parent children
	if !slices.ContainsFunc(cachedProcessParent.Children, func(c *processlist.ProcessNode) bool {
		return pc.ProcessMatches(cachedProcessChild, c)
	}) {
		return false
	}

	// validate process / exec links

	// 1/ for parent
	cachedExecParent := pl.GetCacheExec(pc.GetExecCacheKey(&parent.ProcessContext.Process))
	if cachedExecParent == nil {
		return false
	}
	if !slices.ContainsFunc(cachedProcessParent.PossibleExecs, func(e *processlist.ExecNode) bool {
		return pc.ExecMatches(e, cachedExecParent)
	}) {
		return false
	}
	if cachedExecParent.ProcessLink != cachedProcessParent {
		return false
	}

	// 1/ for child
	cachedExecChild := pl.GetCacheExec(pc.GetExecCacheKey(&child.ProcessContext.Process))
	if cachedExecChild == nil {
		return false
	}
	if !slices.ContainsFunc(cachedProcessChild.PossibleExecs, func(e *processlist.ExecNode) bool {
		return pc.ExecMatches(e, cachedExecChild)
	}) {
		return false
	}
	if cachedExecChild.ProcessLink != cachedProcessChild {
		return false
	}
	return true
}

func isProcessAndExecPresent(pl *processlist.ProcessList, pc *ProcessResolver, event *model.Event) bool {
	// first, get cached process
	cachedProcess := pl.GetCacheProcess(pc.GetProcessCacheKey(&event.ProcessContext.Process))
	if cachedProcess == nil {
		return false
	}

	// validate process / exec links
	cachedExec := pl.GetCacheExec(pc.GetExecCacheKey(&event.ProcessContext.Process))
	if cachedExec == nil {
		return false
	}
	if !slices.ContainsFunc(cachedProcess.PossibleExecs, func(e *processlist.ExecNode) bool {
		return pc.ExecMatches(e, cachedExec)
	}) {
		return false
	}
	if cachedExec.ProcessLink != cachedProcess {
		return false
	}
	return true
}

func isProcessOrExecPresent(pl *processlist.ProcessList, pc *ProcessResolver, event *model.Event) bool {
	// first, check process presence
	cachedProcess := pl.GetCacheProcess(pc.GetProcessCacheKey(&event.ProcessContext.Process))
	if cachedProcess != nil {
		return true
	}

	// then exec
	cachedExec := pl.GetCacheExec(pc.GetExecCacheKey(&event.ProcessContext.Process))
	if cachedExec != nil {
		return true
	}
	return false
}

func TestFork1st(t *testing.T) {
	pc := NewProcessResolver()
	processList := processlist.NewProcessList(cgroupModel.WorkloadSelector{Image: "*", Tag: "*"},
		[]model.EventType{model.ExecEventType, model.ForkEventType, model.ExitEventType}, pc /* ,nil  */, nil, nil)
	stats := testStats{}

	// parent
	parent := newFakeExecEvent(0, 1, "/bin/parent")
	inserted, err := processList.Insert(parent, true, "")
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, true, inserted)
	stats.AddProcess(1)
	stats.ValidateCounters(t, processList)
	if !isProcessAndExecPresent(processList, pc, parent) {
		t.Fatal("didn't found cached parent")
	}

	// parent
	//     \ child
	child := newFakeExecEvent(1, 2, "/bin/child")
	inserted, err = processList.Insert(child, true, "")
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, true, inserted)
	stats.AddProcess(1)
	stats.ValidateCounters(t, processList)
	if checkParentality(processList, pc, parent, child) == false {
		t.Fatal("parent / child paternality not found")
	}

	// parent
	child.Type = uint32(model.ExitEventType)
	deleted, err := processList.Insert(child, true, "")
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, true, deleted)
	stats.DeleteProcess(1)
	stats.ValidateCounters(t, processList)
	if !isProcessAndExecPresent(processList, pc, parent) {
		t.Fatal("didn't found cached parent")
	}
	if isProcessOrExecPresent(processList, pc, child) {
		t.Fatal("child still present")
	}

	// nothing
	deleted, err = processList.DeleteCachedProcess(pc.GetProcessCacheKey(&parent.ProcessContext.Process), "")
	assert.Equal(t, true, deleted)
	stats.DeleteProcess(1)
	stats.ValidateCounters(t, processList)
	if isProcessOrExecPresent(processList, pc, parent) {
		t.Fatal("parent still present")
	}
}

//
// TODO: tests from pkg/security/resolvers/process/resolver_test.go to add:
//

func TestFork2nd(t *testing.T) {
	pc := NewProcessResolver()
	processList := processlist.NewProcessList(cgroupModel.WorkloadSelector{Image: "*", Tag: "*"},
		[]model.EventType{model.ExecEventType, model.ForkEventType, model.ExitEventType}, pc /* ,nil  */, nil, nil)
	stats := testStats{}

	// parent
	parent := newFakeExecEvent(0, 1, "/bin/parent")
	new, err := processList.Insert(parent, true, "")
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, true, new)
	stats.AddProcess(1)
	stats.ValidateCounters(t, processList)

	if !isProcessAndExecPresent(processList, pc, parent) {
		t.Fatal("didn't found cached parent")
	}

	// parent
	//     \ child
	child := newFakeExecEvent(1, 2, "/bin/child")
	new, err = processList.Insert(child, true, "")
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, true, new)
	stats.AddProcess(1)
	stats.ValidateCounters(t, processList)
	if checkParentality(processList, pc, parent, child) == false {
		t.Fatal("parent / child paternality not found")
	}

	// [parent]
	//     \ [child]
	parent.Type = uint32(model.ExitEventType)
	deleted, err := processList.Insert(parent, true, "")
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, true, deleted)

	// Parent process should be removed
	stats.DeleteProcess(1)
	// Child process should be removed
	stats.DeleteProcess(1)
	stats.ValidateCounters(t, processList)
	if isProcessOrExecPresent(processList, pc, parent) {
		t.Fatal("parent still present")
	}
	if isProcessOrExecPresent(processList, pc, child) {
		t.Fatal("child still present")
	}

}
func TestForkExec(t *testing.T) {

	pc := NewProcessResolver()
	processList := processlist.NewProcessList(cgroupModel.WorkloadSelector{Image: "*", Tag: "*"},
		[]model.EventType{model.ExecEventType, model.ForkEventType, model.ExitEventType}, pc /* ,nil  */, nil, nil)
	stats := testStats{}

	// parent
	parent := newFakeExecEvent(0, 1, "/bin/parent")
	new, err := processList.Insert(parent, true, "")
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, true, new)
	stats.AddProcess(1)
	stats.ValidateCounters(t, processList)
	if !isProcessAndExecPresent(processList, pc, parent) {
		t.Fatal("didn't found cached parent")
	}

	// parent
	//     \ child
	child := newFakeExecEvent(1, 2, "/bin/child")
	new, err = processList.Insert(child, true, "")
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, true, new)
	stats.AddProcess(1)
	stats.ValidateCounters(t, processList)
	if checkParentality(processList, pc, parent, child) == false {
		t.Fatal("parent / child paternality not found")
	}

	// parent
	//     \ child -> exec
	exec := newFakeExecEvent(1, 2, "bin/exec")
	new, err = processList.Insert(exec, true, "")
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, true, new)
	if checkParentality(processList, pc, parent, exec) == false {
		t.Fatal("parent / exec paternality not found")
	}
	stats.AddExec()
	stats.ValidateCounters(t, processList)

	// nothing
	deleted, err := processList.DeleteProcess(pc.GetProcessCacheKey(&parent.ProcessContext.Process), "")
	assert.Equal(t, true, deleted)
	stats.DeleteProcess(1) // For parent
	stats.DeleteProcess(2) // For child
	stats.ValidateCounters(t, processList)
	if isProcessOrExecPresent(processList, pc, parent) {
		t.Fatal("parent still present")
	}

}
func TestForkExecExec(t *testing.T) {
	pc := NewProcessResolver()
	processList := processlist.NewProcessList(cgroupModel.WorkloadSelector{Image: "*", Tag: "*"},
		[]model.EventType{model.ExecEventType, model.ForkEventType, model.ExitEventType}, pc /* ,nil  */, nil, nil)
	stats := testStats{}

	// parent
	parent := newFakeExecEvent(0, 1, "/bin/parent")
	new, err := processList.Insert(parent, true, "")
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, true, new)
	stats.AddProcess(1)
	stats.ValidateCounters(t, processList)
	if !isProcessAndExecPresent(processList, pc, parent) {
		t.Fatal("didn't found cached parent")
	}

	// parent
	//     \ child
	child := newFakeExecEvent(1, 2, "/bin/child")
	new, err = processList.Insert(child, true, "")
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, true, new)
	stats.AddProcess(1)
	stats.ValidateCounters(t, processList)
	if checkParentality(processList, pc, parent, child) == false {
		t.Fatal("parent / child paternality not found")
	}

	// parent
	//     \ child -> exec1
	exec1 := newFakeExecEvent(1, 2, "bin/exec1")
	new, err = processList.Insert(exec1, true, "")
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, true, new)
	if checkParentality(processList, pc, parent, exec1) == false {
		t.Fatal("parent / exec paternality not found")
	}
	stats.AddExec()
	stats.ValidateCounters(t, processList)

	// [parent]
	//     \ child -> exec1 -> exec2
	exec2 := newFakeExecEvent(1, 2, "bin/exec2")
	new, err = processList.Insert(exec2, true, "")
	if err != nil {
		t.Fatal(err)
	}
	if checkParentality(processList, pc, parent, exec2) == false {
		t.Fatal("parent / exec paternality not found")
	}
	assert.Equal(t, true, new)
	stats.AddExec()
	stats.ValidateCounters(t, processList)

	// nothing
	deleted, err := processList.DeleteProcess(pc.GetProcessCacheKey(&parent.ProcessContext.Process), "")
	assert.Equal(t, true, deleted)
	stats.DeleteProcess(1) // For parent
	stats.DeleteProcess(3) // For child
	stats.ValidateCounters(t, processList)
	if isProcessOrExecPresent(processList, pc, parent) {
		t.Fatal("parent still present")
	}
}
func TestOrphanExec(t *testing.T) {

	pc := NewProcessResolver()
	processList := processlist.NewProcessList(cgroupModel.WorkloadSelector{Image: "*", Tag: "*"},
		[]model.EventType{model.ExecEventType, model.ForkEventType, model.ExitEventType}, pc /* ,nil  */, nil, nil)
	stats := testStats{}

	// parent
	parent := newFakeExecEvent(0, 1, "/bin/parent")
	new, err := processList.Insert(parent, true, "")
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, true, new)
	stats.AddProcess(1)
	stats.ValidateCounters(t, processList)
	if !isProcessAndExecPresent(processList, pc, parent) {
		t.Fatal("didn't found cached parent")
	}

	// parent
	//     \ child
	child := newFakeExecEvent(1, 2, "/bin/child")
	new, err = processList.Insert(child, true, "")
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, true, new)
	stats.AddProcess(1)
	stats.ValidateCounters(t, processList)
	if checkParentality(processList, pc, parent, child) == false {
		t.Fatal("parent / child paternality not found")
	}

	// [parent]
	//     \ [child]

	deleted, err := processList.DeleteProcess(pc.GetProcessCacheKey(&parent.ProcessContext.Process), "")
	assert.Equal(t, true, deleted)
	stats.DeleteProcess(1) // For parent
	stats.DeleteProcess(1) // For child
	stats.ValidateCounters(t, processList)
	if isProcessOrExecPresent(processList, pc, parent) {
		t.Fatal("parent still present")
	}
	if isProcessOrExecPresent(processList, pc, child) {
		t.Fatal("child still present")
	}

	// [parent]
	//     \ [child] -> exec
	exec := newFakeExecEvent(1, 2, "bin/exec")
	new, err = processList.Insert(exec, true, "")
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, false, new)
}
func TestForkReuse(t *testing.T) {
	// resolver, err := NewEBPFResolver(nil, nil, &statsd.NoOpClient{}, nil, nil, nil, nil, nil, nil, nil, NewResolverOpts())
	// if err != nil {
	// 	t.Fatal(err)
	// }

	// parent1 := resolver.NewProcessCacheEntry(model.PIDContext{Pid: 1, Tid: 1})
	// parent1.ForkTime = time.Now()

	// child1 := resolver.NewProcessCacheEntry(model.PIDContext{Pid: 2, Tid: 2})
	// child1.PPid = parent1.Pid
	// child1.ForkTime = time.Now()

	// exec1 := resolver.NewProcessCacheEntry(model.PIDContext{Pid: child1.Pid, Tid: child1.Pid})
	// exec1.PPid = child1.PPid
	// exec1.FileEvent.Inode = 123
	// exec1.ExecTime = time.Now()

	// parent2 := resolver.NewProcessCacheEntry(model.PIDContext{Pid: 1, Tid: 1})
	// parent2.ForkTime = time.Now()

	// child2 := resolver.NewProcessCacheEntry(model.PIDContext{Pid: 3, Tid: 3})
	// child2.PPid = parent2.Pid
	// child2.ForkTime = time.Now()

	// // parent1
	// resolver.AddForkEntry(parent1, 0)
	// assert.Equal(t, parent1, resolver.entryCache[parent1.Pid])
	// assert.Equal(t, 1, len(resolver.entryCache))
	// assert.EqualValues(t, 1, resolver.cacheSize.Load())

	// // parent1
	// //     \ child1
	// resolver.AddForkEntry(child1, 0)
	// assert.Equal(t, child1, resolver.entryCache[child1.Pid])
	// assert.Equal(t, 2, len(resolver.entryCache))
	// assert.Equal(t, parent1, child1.Ancestor)
	// assert.EqualValues(t, 2, resolver.cacheSize.Load())

	// // [parent1]
	// //     \ child1
	// resolver.DeleteEntry(parent1.Pid, time.Now())
	// assert.Nil(t, resolver.entryCache[parent1.Pid])
	// assert.Equal(t, 1, len(resolver.entryCache))
	// assert.Equal(t, parent1, child1.Ancestor)

	// // [parent1]
	// //     \ [child1] -> exec1
	// resolver.AddExecEntry(exec1, 0)
	// assert.Equal(t, exec1, resolver.entryCache[exec1.Pid])
	// assert.Equal(t, 1, len(resolver.entryCache))
	// assert.Equal(t, child1, exec1.Ancestor)
	// assert.Equal(t, parent1, exec1.Ancestor.Ancestor)
	// assert.EqualValues(t, 3, resolver.cacheSize.Load())

	// // [parent1:pid1]
	// //     \ [child1] -> exec1
	// //
	// // parent2:pid1
	// resolver.AddForkEntry(parent2, 0)
	// assert.Equal(t, parent2, resolver.entryCache[parent2.Pid])
	// assert.Equal(t, 2, len(resolver.entryCache))
	// assert.EqualValues(t, 4, resolver.cacheSize.Load())

	// // [parent1:pid1]
	// //     \ [child1] -> exec1
	// //
	// // parent2:pid1
	// //     \ child2
	// resolver.AddForkEntry(child2, 0)
	// assert.Equal(t, child2, resolver.entryCache[child2.Pid])
	// assert.Equal(t, 3, len(resolver.entryCache))
	// assert.Equal(t, parent2, child2.Ancestor)
	// assert.EqualValues(t, 5, resolver.cacheSize.Load())

	// // parent2:pid1
	// //     \ child2
	// resolver.DeleteEntry(exec1.Pid, time.Now())
	// assert.Nil(t, resolver.entryCache[exec1.Pid])
	// assert.Equal(t, 2, len(resolver.entryCache))

	// // [parent2:pid1]
	// //     \ child2
	// resolver.DeleteEntry(parent2.Pid, time.Now())
	// assert.Nil(t, resolver.entryCache[parent2.Pid])
	// assert.Equal(t, 1, len(resolver.entryCache))
	// assert.Equal(t, parent2, child2.Ancestor)

	// // nothing
	// resolver.DeleteEntry(child2.Pid, time.Now())
	// assert.Zero(t, len(resolver.entryCache))

	// testCacheSize(t, resolver)
}
func TestForkForkExec(t *testing.T) {

	pc := NewProcessResolver()
	processList := processlist.NewProcessList(cgroupModel.WorkloadSelector{Image: "*", Tag: "*"},
		[]model.EventType{model.ExecEventType, model.ForkEventType, model.ExitEventType}, pc /* ,nil  */, nil, nil)
	stats := testStats{}

	// parent
	parent := newFakeExecEvent(0, 1, "/bin/parent")
	new, err := processList.Insert(parent, true, "")
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, true, new)
	stats.AddProcess(1)
	stats.ValidateCounters(t, processList)
	if !isProcessAndExecPresent(processList, pc, parent) {
		t.Fatal("didn't found cached parent")
	}

	// parent
	//     \ child
	child := newFakeExecEvent(1, 2, "/bin/child")
	new, err = processList.Insert(child, true, "")
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, true, new)
	stats.AddProcess(1)
	stats.ValidateCounters(t, processList)
	if checkParentality(processList, pc, parent, child) == false {
		t.Fatal("parent / child paternality not found")
	}

	// parent
	//     \ child
	//          \ grandChild
	grandChild := newFakeExecEvent(2, 3, "/bin/grandChild")
	new, err = processList.Insert(grandChild, true, "")
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, true, new)
	stats.AddProcess(1)
	stats.ValidateCounters(t, processList)
	if checkParentality(processList, pc, child, grandChild) == false {
		t.Fatal("child / grandChild paternality not found")
	}

	// parent
	//     \ child -> childEdex
	//          \ grandChild
	childExec := newFakeExecEvent(1, 2, "bin/childExec")
	new, err = processList.Insert(childExec, true, "")
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, true, new)
	if checkParentality(processList, pc, parent, childExec) == false {
		t.Fatal("parent / childExec paternality not found")
	}
	stats.AddExec()
	stats.ValidateCounters(t, processList)

	// nothing
	deleted, err := processList.DeleteProcess(pc.GetProcessCacheKey(&parent.ProcessContext.Process), "")
	assert.Equal(t, true, deleted)
	stats.DeleteProcess(1) // For parent
	stats.DeleteProcess(2) // For child
	stats.DeleteProcess(1) // For grandChild
	stats.ValidateCounters(t, processList)
	if isProcessOrExecPresent(processList, pc, parent) {
		t.Fatal("parent still present")
	}
	if isProcessOrExecPresent(processList, pc, child) {
		t.Fatal("child still present")
	}
	if isProcessOrExecPresent(processList, pc, grandChild) {
		t.Fatal("grandChild still present")
	}
	if isProcessOrExecPresent(processList, pc, childExec) {
		t.Fatal("childExec still present")
	}
}
func TestExecBomb(t *testing.T) {
	// resolver, err := NewEBPFResolver(nil, nil, &statsd.NoOpClient{}, nil, nil, nil, nil, nil, nil, nil, NewResolverOpts())
	// if err != nil {
	// 	t.Fatal(err)
	// }

	// parent := resolver.NewProcessCacheEntry(model.PIDContext{Pid: 1, Tid: 1})
	// parent.ForkTime = time.Now()

	// child := resolver.NewProcessCacheEntry(model.PIDContext{Pid: 2, Tid: 2})
	// child.PPid = parent.Pid
	// child.ForkTime = time.Now()

	// exec1 := resolver.NewProcessCacheEntry(model.PIDContext{Pid: child.Pid, Tid: child.Pid})
	// exec1.PPid = child.PPid
	// exec1.FileEvent.Inode = 123
	// exec1.ExecTime = time.Now()

	// exec2 := resolver.NewProcessCacheEntry(model.PIDContext{Pid: child.Pid, Tid: child.Pid})
	// exec2.Pid = child.Pid
	// exec2.PPid = child.PPid
	// exec2.FileEvent.Inode = 123
	// exec2.ExecTime = time.Now()

	// // parent
	// resolver.AddForkEntry(parent, 0)
	// assert.Equal(t, parent, resolver.entryCache[parent.Pid])
	// assert.Equal(t, 1, len(resolver.entryCache))
	// assert.EqualValues(t, 1, resolver.cacheSize.Load())

	// // parent
	// //     \ child
	// resolver.AddForkEntry(child, 0)
	// assert.Equal(t, child, resolver.entryCache[child.Pid])
	// assert.Equal(t, 2, len(resolver.entryCache))
	// assert.Equal(t, parent, child.Ancestor)
	// assert.EqualValues(t, 2, resolver.cacheSize.Load())

	// // [parent]
	// //     \ child
	// resolver.DeleteEntry(parent.Pid, time.Now())
	// assert.Nil(t, resolver.entryCache[parent.Pid])
	// assert.Equal(t, 1, len(resolver.entryCache))
	// assert.Equal(t, parent, child.Ancestor)

	// // [parent]
	// //     \ [child] -> exec1
	// resolver.AddExecEntry(exec1, 0)
	// assert.Equal(t, exec1, resolver.entryCache[exec1.Pid])
	// assert.Equal(t, 1, len(resolver.entryCache))
	// assert.Equal(t, child, exec1.Ancestor)
	// assert.Equal(t, parent, exec1.Ancestor.Ancestor)
	// assert.EqualValues(t, 3, resolver.cacheSize.Load())

	// // [parent]
	// //     \ [child] -> [exec1] -> exec2
	// resolver.AddExecEntry(exec2, 0)
	// assert.Equal(t, exec1, resolver.entryCache[exec2.Pid])
	// assert.Equal(t, 1, len(resolver.entryCache))
	// assert.Equal(t, exec1.ExecTime, exec2.ExecTime)
	// assert.EqualValues(t, 3, resolver.cacheSize.Load())

	// // nothing
	// resolver.DeleteEntry(exec1.Pid, time.Now())
	// assert.Zero(t, len(resolver.entryCache))

	// testCacheSize(t, resolver)
}
func TestExecLostFork(t *testing.T) {
	// resolver, err := NewEBPFResolver(nil, nil, &statsd.NoOpClient{}, nil, nil, nil, nil, nil, nil, nil, NewResolverOpts())
	// if err != nil {
	// 	t.Fatal(err)
	// }

	// parent := resolver.NewProcessCacheEntry(model.PIDContext{Pid: 11, Tid: 11})
	// parent.FileEvent.BasenameStr = "agent"
	// parent.ForkTime = time.Now()
	// parent.FileEvent.Inode = 1
	// parent.ExecInode = 1

	// // parent
	// resolver.AddForkEntry(parent, 0)

	// child := resolver.NewProcessCacheEntry(model.PIDContext{Pid: 22, Tid: 22})
	// child.PPid = parent.Pid
	// child.FileEvent.Inode = 1

	// // parent
	// //     \ child
	// resolver.AddForkEntry(child, parent.ExecInode)

	// assert.Equal(t, "agent", child.FileEvent.BasenameStr)
	// assert.False(t, child.IsParentMissing)

	// // exec loss with inode 2

	// child1 := resolver.NewProcessCacheEntry(model.PIDContext{Pid: 33, Tid: 33})
	// child1.FileEvent.BasenameStr = "sh"
	// child1.PPid = child.Pid
	// child1.ExecInode = 2

	// // parent
	// //     \ child
	// //		\ child1
	// resolver.AddForkEntry(child1, child1.ExecInode)

	// assert.Equal(t, "agent", child1.FileEvent.BasenameStr)
	// assert.True(t, child1.IsParentMissing)
}
func TestExecLostExec(t *testing.T) {}
func TestIsExecExecRuntime(t *testing.T) {

	// resolver, err := NewEBPFResolver(nil, nil, &statsd.NoOpClient{}, nil, nil, nil, nil, nil, nil, nil, NewResolverOpts())
	// if err != nil {
	// 	t.Fatal(err)
	// }

	// parent := resolver.NewProcessCacheEntry(model.PIDContext{Pid: 1, Tid: 1})
	// parent.ForkTime = time.Now()
	// parent.FileEvent.Inode = 1

	// // parent
	// resolver.AddForkEntry(parent, 0)

	// child := resolver.NewProcessCacheEntry(model.PIDContext{Pid: 2, Tid: 2})
	// child.PPid = parent.Pid
	// child.FileEvent.Inode = 1

	// // parent
	// //     \ child
	// resolver.AddForkEntry(child, 0)

	// // parent
	// //     \ child
	// //      \ child2

	// child2 := resolver.NewProcessCacheEntry(model.PIDContext{Pid: 2, Tid: 2})
	// child2.FileEvent.Inode = 2
	// child2.PPid = child.Pid
	// resolver.AddExecEntry(child2, 0)

	// // parent
	// //     \ child a
	// //      \ child2
	// //       \ child3

	// child3 := resolver.NewProcessCacheEntry(model.PIDContext{Pid: 2, Tid: 2})
	// child3.FileEvent.Inode = 3
	// child3.PPid = child2.Pid
	// resolver.AddExecEntry(child3, 0)

	// assert.False(t, parent.IsExecExec)
	// assert.False(t, parent.IsThread) // root node, no fork

	// assert.False(t, child.IsExecExec)
	// assert.True(t, child.IsThread)

	// assert.False(t, child2.IsExecExec)
	// assert.False(t, child2.IsThread)

	// assert.True(t, child3.IsExecExec)
	// assert.False(t, child3.IsThread)

	// child4 := resolver.NewProcessCacheEntry(model.PIDContext{Pid: 2, Tid: 2})
	// child4.FileEvent.Inode = 3
	// child4.PPid = child3.Pid
	// resolver.AddExecEntry(child4, 0)

	// assert.True(t, child3.IsExecExec)
	// assert.False(t, child3.IsThread)
}
func TestIsExecExecSnapshot(t *testing.T) {
	// resolver, err := NewEBPFResolver(nil, nil, &statsd.NoOpClient{}, nil, nil, nil, nil, nil, nil, nil, NewResolverOpts())
	// if err != nil {
	// 	t.Fatal(err)
	// }

	// parent := resolver.NewProcessCacheEntry(model.PIDContext{Pid: 1, Tid: 1})
	// parent.ForkTime = time.Now()
	// parent.FileEvent.Inode = 1
	// parent.IsThread = true

	// // parent
	// resolver.insertEntry(parent, nil, model.ProcessCacheEntryFromSnapshot)

	// child := resolver.NewProcessCacheEntry(model.PIDContext{Pid: 2, Tid: 2})
	// child.PPid = parent.Pid
	// child.FileEvent.Inode = 2
	// child.IsThread = true

	// // parent
	// //     \ child

	// resolver.setAncestor(child)
	// resolver.insertEntry(child, nil, model.ProcessCacheEntryFromSnapshot)

	// assert.False(t, parent.IsExecExec)
	// assert.True(t, parent.IsThread) // root node, no fork

	// assert.False(t, child.IsExecExec)
	// assert.True(t, child.IsThread)

	// // parent
	// //     \ child
	// //      \ child2

	// child2 := resolver.NewProcessCacheEntry(model.PIDContext{Pid: 2, Tid: 2})
	// child2.FileEvent.Inode = 3
	// child2.PPid = child.Pid
	// resolver.AddExecEntry(child2, 0)

	// assert.False(t, child2.IsExecExec)
	// assert.False(t, child2.IsThread)

	// child3 := resolver.NewProcessCacheEntry(model.PIDContext{Pid: 2, Tid: 2})
	// child3.FileEvent.Inode = 4
	// child3.PPid = child2.Pid
	// resolver.AddExecEntry(child3, 0)

	// assert.True(t, child3.IsExecExec)
	// assert.False(t, child3.IsThread)
}
