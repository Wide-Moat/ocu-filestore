// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package telemetry

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
)

// escapeLabel escapes a label value per the Prometheus text format spec:
// - backslash -> \\
// - double-quote -> \"
// - newline -> \n
// Closed enums mean real label values are always clean ASCII, but the escaper
// is applied unconditionally for defensive correctness.
func escapeLabel(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	return s
}

// formatLabels builds a sorted, escaped Prometheus label string from a cell key.
// cellKey is the format produced by labelKey(): "k1=v1;k2=v2;".
// For the build_info family it is "version=<raw>".
func formatLabelsFromKey(cellKey string, sortedKeys []string) string {
	if len(cellKey) == 0 {
		return ""
	}
	// Parse "k=v;" pairs.
	pairs := make(map[string]string)
	for _, part := range strings.Split(cellKey, ";") {
		if part == "" {
			continue
		}
		idx := strings.IndexByte(part, '=')
		if idx < 0 {
			continue
		}
		pairs[part[:idx]] = part[idx+1:]
	}

	// Output in sorted key order for determinism.
	keys := sortedKeys
	if len(keys) == 0 {
		// Derive from pairs if sortedKeys is empty (build_info case).
		keys = make([]string, 0, len(pairs))
		for k := range pairs {
			keys = append(keys, k)
		}
		sort.Strings(keys)
	}

	var sb strings.Builder
	sb.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			sb.WriteByte(',')
		}
		fmt.Fprintf(&sb, `%s="%s"`, k, escapeLabel(pairs[k]))
	}
	sb.WriteByte('}')
	return sb.String()
}

// writeCounter writes one counter family to w.
func writeCounter(w io.Writer, c *Counter) {
	fmt.Fprintf(w, "# HELP %s %s\n", c.name, c.help)
	fmt.Fprintf(w, "# TYPE %s counter\n", c.name)

	c.mu.Lock()
	cells := make(map[string]uint64, len(c.cells))
	for k, v := range c.cells {
		cells[k] = v
	}
	c.mu.Unlock()

	// Sort cell keys for deterministic output.
	keys := make([]string, 0, len(cells))
	for k := range cells {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		labels := formatLabelsFromKey(k, c.sortedK)
		fmt.Fprintf(w, "%s%s %d\n", c.name, labels, cells[k])
	}
}

// writeGauge writes one gauge family to w.
func writeGauge(w io.Writer, g *Gauge) {
	fmt.Fprintf(w, "# HELP %s %s\n", g.name, g.help)
	fmt.Fprintf(w, "# TYPE %s gauge\n", g.name)

	g.mu.Lock()
	cells := make(map[string]float64, len(g.cells))
	for k, v := range g.cells {
		cells[k] = v
	}
	g.mu.Unlock()

	keys := make([]string, 0, len(cells))
	for k := range cells {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		labels := formatLabelsFromKey(k, g.sortedK)
		fmt.Fprintf(w, "%s%s %s\n", g.name, labels, formatFloat(cells[k]))
	}
}

// writeBuildInfo writes the build_info gauge in the special
// build_info{version="..."} 1 format.
func writeBuildInfo(w io.Writer, g *Gauge) {
	g.mu.Lock()
	cells := make(map[string]float64, len(g.cells))
	for k, v := range g.cells {
		cells[k] = v
	}
	g.mu.Unlock()

	fmt.Fprintf(w, "# HELP %s %s\n", g.name, g.help)
	fmt.Fprintf(w, "# TYPE %s gauge\n", g.name)

	// build_info cell key is "version=<raw>". We extract the raw value and
	// escape it for the label string.
	keys := make([]string, 0, len(cells))
	for k := range cells {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		// key is "version=<raw>". Extract the raw version.
		raw := strings.TrimPrefix(k, "version=")
		fmt.Fprintf(w, `%s{version="%s"} %s`+"\n", g.name, escapeLabel(raw), formatFloat(cells[k]))
	}
}

// writeHistogram writes one histogram family to w.
func writeHistogram(w io.Writer, h *Histogram) {
	fmt.Fprintf(w, "# HELP %s %s\n", h.name, h.help)
	fmt.Fprintf(w, "# TYPE %s histogram\n", h.name)

	h.mu.Lock()
	type cellSnap struct {
		key  string
		cell histCell
	}
	snaps := make([]cellSnap, 0, len(h.cells))
	for k, c := range h.cells {
		bs := make([]uint64, len(c.buckets))
		copy(bs, c.buckets)
		snaps = append(snaps, cellSnap{key: k, cell: histCell{count: c.count, sum: c.sum, buckets: bs}})
	}
	bounds := h.bounds
	sortedK := h.sortedK
	h.mu.Unlock()

	// Sort by cell key for determinism.
	sort.Slice(snaps, func(i, j int) bool { return snaps[i].key < snaps[j].key })

	for _, snap := range snaps {
		labels := formatLabelsFromKey(snap.key, sortedK)
		labelBase := snap.key

		// Build the label string without outer braces for extended labels.
		innerLabels := ""
		if labels != "" && labels != "{}" {
			// Strip the outer braces for building extended bucket labels.
			innerLabels = labels[1 : len(labels)-1] // remove { and }
		}

		// Bucket lines: one per bound + +Inf.
		cumulativeCount := uint64(0)
		for i, bound := range bounds {
			cumulativeCount += snap.cell.buckets[i]
			leStr := formatFloat(bound)
			var bucketLabel string
			if innerLabels != "" {
				bucketLabel = fmt.Sprintf(`{le="%s",%s}`, leStr, innerLabels)
			} else {
				bucketLabel = fmt.Sprintf(`{le="%s"}`, leStr)
			}
			fmt.Fprintf(w, "%s_bucket%s %d\n", h.name, bucketLabel, cumulativeCount)
		}
		// +Inf bucket equals the total count.
		var infLabel string
		if innerLabels != "" {
			infLabel = fmt.Sprintf(`{le="+Inf",%s}`, innerLabels)
		} else {
			infLabel = `{le="+Inf"}`
		}
		fmt.Fprintf(w, "%s_bucket%s %d\n", h.name, infLabel, snap.cell.count)

		// _sum and _count with original label set.
		_ = labelBase
		fmt.Fprintf(w, "%s_sum%s %s\n", h.name, labels, formatFloat(snap.cell.sum))
		fmt.Fprintf(w, "%s_count%s %d\n", h.name, labels, snap.cell.count)
	}
}

// formatFloat renders a float64 in the most compact form Prometheus accepts.
// Prometheus text format allows any valid Go float representation.
func formatFloat(f float64) string {
	return strconv.FormatFloat(f, 'g', -1, 64)
}
