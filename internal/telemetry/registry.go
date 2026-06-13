// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package telemetry provides a hand-rolled Prometheus text-exposition endpoint,
// a concurrency-safe metric registry with closed label-set validation, and the
// concrete broker metric set. Zero new dependencies — stdlib only plus
// internal/observ (which is itself stdlib-only).
//
// Dependency discipline: telemetry is a leaf package that does NOT import
// internal/southface or any package that would create a cycle. southface
// depends on telemetry so it can accept a *BrokerMetrics for instrumentation.
// Southface op/deny class names are mirrored here as const strings; the test
// cross-checks that every name in KnownOps/KnownDenyClasses is a value that
// the real southface package uses.
package telemetry

import (
	"fmt"
	"io"
	"sort"
	"sync"
)

// LabelSet declares the allowed label keys and their closed value enums for a
// metric family. Every key must have at least one allowed value. An empty map
// means the metric has no labels.
type LabelSet map[string][]string

// Labels is a set of key-value pairs supplied when recording a metric
// observation. Every key must be present in the family's LabelSet and every
// value must appear in the key's allowed enum.
type Labels map[string]string

// labelSetIndex maps each key to a set of allowed values for O(1) validation.
type labelSetIndex map[string]map[string]struct{}

func buildIndex(ls LabelSet) labelSetIndex {
	idx := make(labelSetIndex, len(ls))
	for k, vals := range ls {
		m := make(map[string]struct{}, len(vals))
		for _, v := range vals {
			m[v] = struct{}{}
		}
		idx[k] = m
	}
	return idx
}

// validateLabels panics on any constraint violation — a caller passing an
// out-of-enum or missing label is a wiring bug, not a runtime condition.
func validateLabels(idx labelSetIndex, got Labels) {
	if len(got) != len(idx) {
		panic(fmt.Sprintf("telemetry: label count mismatch: expected %d keys, got %d", len(idx), len(got)))
	}
	for k, allowed := range idx {
		v, ok := got[k]
		if !ok {
			panic(fmt.Sprintf("telemetry: label key %q missing from supplied Labels", k))
		}
		if _, valid := allowed[v]; !valid {
			panic(fmt.Sprintf("telemetry: label key %q: value %q is not in the closed enum", k, v))
		}
	}
}

// sortedKeys returns the label keys in deterministic (sorted) order.
func sortedKeys(ls LabelSet) []string {
	keys := make([]string, 0, len(ls))
	for k := range ls {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// labelKey is an internal map key derived by sorting label pairs
// deterministically. It is used as the map key for per-labelset metric cells.
func labelKey(labels Labels) string {
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var key string
	for _, k := range keys {
		key += k + "=" + labels[k] + ";"
	}
	return key
}

// HistogramSnapshot is a point-in-time snapshot of a histogram cell.
type HistogramSnapshot struct {
	Count   uint64
	Sum     float64
	Buckets []uint64 // len == len(declared buckets), parallel to bucket boundaries
}

// --- Counter ---

// Counter is a concurrency-safe monotonically increasing counter.
type Counter struct {
	mu      sync.Mutex
	name    string
	help    string
	idx     labelSetIndex
	sortedK []string
	cells   map[string]uint64
}

// Inc increments the counter for the given labels by one.
func (c *Counter) Inc(labels Labels) {
	validateLabels(c.idx, labels)
	k := labelKey(labels)
	c.mu.Lock()
	c.cells[k]++
	c.mu.Unlock()
}

// Add increments the counter for the given labels by n.
func (c *Counter) Add(labels Labels, n uint64) {
	validateLabels(c.idx, labels)
	k := labelKey(labels)
	c.mu.Lock()
	c.cells[k] += n
	c.mu.Unlock()
}

// --- Gauge ---

// Gauge is a concurrency-safe gauge (can go up or down).
type Gauge struct {
	mu      sync.Mutex
	name    string
	help    string
	idx     labelSetIndex
	sortedK []string
	cells   map[string]float64
}

// Set sets the gauge to value for the given labels.
func (g *Gauge) Set(labels Labels, value float64) {
	validateLabels(g.idx, labels)
	k := labelKey(labels)
	g.mu.Lock()
	g.cells[k] = value
	g.mu.Unlock()
}

// Current returns the current value for the given labels.
func (g *Gauge) Current(labels Labels) float64 {
	validateLabels(g.idx, labels)
	k := labelKey(labels)
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.cells[k]
}

// --- Histogram ---

// histCell is one per-label-combination accumulator.
type histCell struct {
	count   uint64
	sum     float64
	buckets []uint64 // parallel to histogram.bounds
}

// Histogram is a concurrency-safe Prometheus histogram.
type Histogram struct {
	mu      sync.Mutex
	name    string
	help    string
	bounds  []float64 // upper bounds, excludes +Inf
	idx     labelSetIndex
	sortedK []string
	cells   map[string]*histCell
}

// Observe records a single observation of value under the given labels.
func (h *Histogram) Observe(labels Labels, value float64) {
	validateLabels(h.idx, labels)
	k := labelKey(labels)
	h.mu.Lock()
	cell, ok := h.cells[k]
	if !ok {
		cell = &histCell{buckets: make([]uint64, len(h.bounds))}
		h.cells[k] = cell
	}
	cell.count++
	cell.sum += value
	for i, bound := range h.bounds {
		if value <= bound {
			cell.buckets[i]++
		}
	}
	h.mu.Unlock()
}

// Snapshot returns a point-in-time copy of the histogram cell for labels.
func (h *Histogram) Snapshot(labels Labels) HistogramSnapshot {
	validateLabels(h.idx, labels)
	k := labelKey(labels)
	h.mu.Lock()
	defer h.mu.Unlock()
	cell, ok := h.cells[k]
	if !ok {
		return HistogramSnapshot{Buckets: make([]uint64, len(h.bounds))}
	}
	bs := make([]uint64, len(cell.buckets))
	copy(bs, cell.buckets)
	return HistogramSnapshot{Count: cell.count, Sum: cell.sum, Buckets: bs}
}

// --- Registry ---

// metric is the union type for the registry's families.
type metric struct {
	kind      string // "counter", "gauge", "histogram"
	name      string
	help      string
	counter   *Counter
	gauge     *Gauge
	histogram *Histogram
}

// Registry holds all registered metric families. Metrics must be registered
// at startup before any goroutine calls Inc/Set/Observe; after that the
// registry is read-only (adding new families mid-flight is not supported).
type Registry struct {
	mu      sync.RWMutex
	metrics []metric // ordered by registration; WriteTo preserves that order
}

// NewRegistry creates an empty Registry.
func NewRegistry() *Registry {
	return &Registry{}
}

// NewCounter registers and returns a new Counter family.
func (r *Registry) NewCounter(name, help string, ls LabelSet) *Counter {
	c := &Counter{
		name:    name,
		help:    help,
		idx:     buildIndex(ls),
		sortedK: sortedKeys(ls),
		cells:   make(map[string]uint64),
	}
	r.mu.Lock()
	r.metrics = append(r.metrics, metric{kind: "counter", name: name, help: help, counter: c})
	r.mu.Unlock()
	return c
}

// NewGauge registers and returns a new Gauge family.
func (r *Registry) NewGauge(name, help string, ls LabelSet) *Gauge {
	g := &Gauge{
		name:    name,
		help:    help,
		idx:     buildIndex(ls),
		sortedK: sortedKeys(ls),
		cells:   make(map[string]float64),
	}
	r.mu.Lock()
	r.metrics = append(r.metrics, metric{kind: "gauge", name: name, help: help, gauge: g})
	r.mu.Unlock()
	return g
}

// NewHistogram registers and returns a new Histogram family.
func (r *Registry) NewHistogram(name, help string, bounds []float64, ls LabelSet) *Histogram {
	h := &Histogram{
		name:    name,
		help:    help,
		bounds:  bounds,
		idx:     buildIndex(ls),
		sortedK: sortedKeys(ls),
		cells:   make(map[string]*histCell),
	}
	r.mu.Lock()
	r.metrics = append(r.metrics, metric{kind: "histogram", name: name, help: help, histogram: h})
	r.mu.Unlock()
	return h
}

// NewBuildInfo registers and returns a build_info gauge set to 1, carrying the
// version as a label value. The version string is exposition-escaped in WriteTo.
// This is the canonical way to expose the daemon build version as a Prometheus
// info metric.
func (r *Registry) NewBuildInfo(version string) *Gauge {
	// build_info is a gauge with a "version" label; the label is NOT in the
	// closed-enum set (it is a free-form string from the build system), so we
	// bypass the normal NewGauge API and store it as a raw gauge cell.
	g := &Gauge{
		name:    "build_info",
		help:    "Daemon build information.",
		idx:     labelSetIndex{}, // bypassed — we set the cell directly below
		sortedK: []string{},
		cells:   make(map[string]float64),
	}
	// Store the raw key so WriteTo can rebuild the label string.
	// We encode the version in the cell key as "version=<raw>" and
	// WriteTo handles the escaping.
	cellKey := "version=" + version
	g.cells[cellKey] = 1.0

	r.mu.Lock()
	r.metrics = append(r.metrics, metric{kind: "build_info", name: "build_info", help: g.help, gauge: g})
	r.mu.Unlock()
	return g
}

// countingWriter wraps an io.Writer and counts bytes written.
type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

// WriteTo renders all registered metric families in Prometheus text format
// 0.0.4 to w. It satisfies io.WriterTo. It holds only the per-family read
// locks; callers must not register new metrics concurrently (registration
// is startup-only).
func (r *Registry) WriteTo(w io.Writer) (int64, error) {
	r.mu.RLock()
	metrics := make([]metric, len(r.metrics))
	copy(metrics, r.metrics)
	r.mu.RUnlock()

	cw := &countingWriter{w: w}
	for _, m := range metrics {
		switch m.kind {
		case "counter":
			writeCounter(cw, m.counter)
		case "gauge":
			writeGauge(cw, m.gauge)
		case "histogram":
			writeHistogram(cw, m.histogram)
		case "build_info":
			writeBuildInfo(cw, m.gauge)
		}
	}
	return cw.n, nil
}
