// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf

package postgres

import (
	"sync"

	"github.com/DataDog/datadog-agent/pkg/network/config"
	netebpf "github.com/DataDog/datadog-agent/pkg/network/ebpf"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

// StatKeeper is a struct to hold the records for the postgres protocol
type StatKeeper struct {
	stats      map[Key]*RequestStat
	statsMutex sync.RWMutex
	maxEntries int

	databaseNamesCache map[netebpf.ConnTuple]string
}

// NewStatkeeper creates a new StatKeeper
func NewStatkeeper(c *config.Config) *StatKeeper {
	newStatKeeper := &StatKeeper{
		maxEntries:         c.MaxPostgresStatsBuffered,
		databaseNamesCache: make(map[netebpf.ConnTuple]string),
	}
	newStatKeeper.resetNoLock()
	return newStatKeeper
}

// Process processes the postgres transaction
func (s *StatKeeper) Process(tx *EventWrapper) {
	s.statsMutex.Lock()
	defer s.statsMutex.Unlock()

	if tx.Tx.Startup_flags == StartupEvent {
		parameters := parsePostgresParameters(tx.Tx.getFragment())
		s.registerDatabaseName(tx.Tuple, parameters.getDatabaseName())
		return
	}

	if tx.Tx.Startup_flags == TerminationEvent {
		s.unregisterDatabaseName(tx.Tuple)
		return
	}

	key := Key{
		DatabaseName:  s.getDatabaseName(tx.Tuple),
		Operation:     tx.Operation(),
		TableName:     tx.TableName(),
		ConnectionKey: tx.ConnTuple(),
	}
	requestStats, ok := s.stats[key]
	if !ok {
		if len(s.stats) >= s.maxEntries {
			return
		}
		requestStats = new(RequestStat)
		s.stats[key] = requestStats
	}
	requestStats.StaticTags = uint64(tx.Tx.Tags)
	requestStats.Count++
	if requestStats.Count == 1 {
		requestStats.FirstLatencySample = tx.RequestLatency()
		return
	}
	if requestStats.Latencies == nil {
		if err := requestStats.initSketch(); err != nil {
			return
		}
		if err := requestStats.Latencies.Add(requestStats.FirstLatencySample); err != nil {
			return
		}
	}
	if err := requestStats.Latencies.Add(tx.RequestLatency()); err != nil {
		log.Debugf("could not add request latency to ddsketch: %v", err)
	}
}

// GetAndResetAllStats returns all the records and resets the statskeeper
func (s *StatKeeper) GetAndResetAllStats() map[Key]*RequestStat {
	s.statsMutex.RLock()
	defer s.statsMutex.RUnlock()
	ret := s.stats // No deep copy needed since `s.statskeeper` gets reset
	s.resetNoLock()
	return ret
}

func (s *StatKeeper) resetNoLock() {
	s.stats = make(map[Key]*RequestStat)
}

// getDatabaseName wraps access to the database name cache, return an
// empty name if there is no entry for the given tuple.
func (s *StatKeeper) getDatabaseName(tuple netebpf.ConnTuple) string {
	if name, ok := s.databaseNamesCache[tuple]; ok {
		return name
	}

	return ""
}

// registerDatabaseName wraps the insertion of database name in the
// database name cache.
func (s *StatKeeper) registerDatabaseName(tuple netebpf.ConnTuple, name string) {
	s.databaseNamesCache[tuple] = name
	log.Debugf("Postgres statskeeper: registering db name: %v; cache size: %v", name, len(s.databaseNamesCache))
}

// unregisterDatabaseName wraps the eviction of database name from the
// database name cache.
func (s *StatKeeper) unregisterDatabaseName(tuple netebpf.ConnTuple) {
	if name, ok := s.databaseNamesCache[tuple]; ok {
		log.Debugf("Postgres statskeeper: unregistering db name: %v; cache size: %v", name, len(s.databaseNamesCache)-1)
	}
	delete(s.databaseNamesCache, tuple)
}
