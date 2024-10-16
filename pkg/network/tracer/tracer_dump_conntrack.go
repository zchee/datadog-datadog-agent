// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf

package tracer

import (
	"fmt"
	"io"
	"slices"

	"golang.org/x/exp/maps"

	"github.com/DataDog/datadog-agent/pkg/network/netlink"
)

// DebugConntrackTable contains conntrack table data used for debugging NAT
type DebugConntrackTable struct {
	Kind    string
	RootNS  uint32
	Entries map[uint32][]netlink.DebugConntrackEntry
}

// WriteTo dumps the conntrack table in the style of `conntrack -L`.
// It sorts the output so that equivalent tables should result in the same text.
func (table *DebugConntrackTable) WriteTo(w io.Writer, maxEntries int) error {
	_, err := fmt.Fprintf(w, "conntrack dump, kind=%s rootNS=%d\n", table.Kind, table.RootNS)
	if err != nil {
		return err
	}

	namespaces := maps.Keys(table.Entries)
	slices.Sort(namespaces)

	totalEntries := 0
	for _, ns := range namespaces {
		totalEntries += len(table.Entries[ns])
	}

	suffix := "\n"
	if totalEntries > maxEntries {
		suffix = fmt.Sprintf(", capped to %d to reduce output size\n", maxEntries)
	}

	_, err = fmt.Fprintf(w, "totalEntries=%d%s", totalEntries, suffix)
	if err != nil {
		return err
	}

	// used to stop writing once we reach maxEntries
	totalEntriesWritten := 0

	for _, ns := range namespaces {
		_, err = fmt.Fprintf(w, "namespace %d, size=%d:\n", ns, len(table.Entries[ns]))
		if err != nil {
			return err
		}
		sortedEntries := slices.Clone(table.Entries[ns])
		slices.SortFunc(sortedEntries, func(a, b netlink.DebugConntrackEntry) int {
			return a.Compare(b)
		})
		for i, entry := range sortedEntries {
			// break out if we have written too much
			if totalEntriesWritten >= maxEntries {
				entriesLeft := len(sortedEntries) - i
				_, err = fmt.Fprintf(w, "<reached max entries, skipping remaining %d entries...>\n", entriesLeft)
				if err != nil {
					return err
				}
				break
			}

			// the entry roughly matches conntrack -L format
			_, err = fmt.Fprintln(w, entry.String())
			if err != nil {
				return err
			}
			totalEntriesWritten++
		}
	}

	return nil
}