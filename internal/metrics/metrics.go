package metrics

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Registry struct {
	reqTotal        atomic.Uint64
	reqErrors       atomic.Uint64
	rateLimited     atomic.Uint64
	instancesActive atomic.Int64
	instancesStarts atomic.Uint64
	instancesStops  atomic.Uint64
	mu              sync.RWMutex
	pathCount       map[string]uint64
	latencyBuckets  map[float64]uint64
	latencyInf      uint64
}

func New() *Registry {
	return &Registry{
		pathCount:      map[string]uint64{},
		latencyBuckets: map[float64]uint64{0.005: 0, 0.01: 0, 0.025: 0, 0.05: 0, 0.1: 0, 0.25: 0, 0.5: 0, 1: 0, 2.5: 0, 5: 0, 10: 0},
	}
}

func (r *Registry) IncRequest(path string) {
	r.reqTotal.Add(1)
	r.mu.Lock()
	r.pathCount[path]++
	r.mu.Unlock()
}
func (r *Registry) IncError()                { r.reqErrors.Add(1) }
func (r *Registry) IncRateLimited()          { r.rateLimited.Add(1) }
func (r *Registry) SetActiveInstances(v int) { r.instancesActive.Store(int64(v)) }
func (r *Registry) IncInstanceStart()        { r.instancesStarts.Add(1) }
func (r *Registry) IncInstanceStop()         { r.instancesStops.Add(1) }

func (r *Registry) ObserveRequestDuration(d time.Duration) {
	secs := d.Seconds()
	r.mu.Lock()
	defer r.mu.Unlock()
	matched := false
	for b := range r.latencyBuckets {
		if secs <= b {
			r.latencyBuckets[b]++
			matched = true
		}
	}
	if !matched {
		r.latencyInf++
	}
}

func (r *Registry) RenderPrometheus() string {
	var b strings.Builder
	fmt.Fprintln(&b, "# HELP lab_agent_requests_total Total API requests")
	fmt.Fprintln(&b, "# TYPE lab_agent_requests_total counter")
	fmt.Fprintf(&b, "lab_agent_requests_total %d\n", r.reqTotal.Load())
	fmt.Fprintln(&b, "# HELP lab_agent_request_errors_total Total API request errors")
	fmt.Fprintln(&b, "# TYPE lab_agent_request_errors_total counter")
	fmt.Fprintf(&b, "lab_agent_request_errors_total %d\n", r.reqErrors.Load())
	fmt.Fprintln(&b, "# HELP lab_agent_rate_limited_total Total rate-limited requests")
	fmt.Fprintln(&b, "# TYPE lab_agent_rate_limited_total counter")
	fmt.Fprintf(&b, "lab_agent_rate_limited_total %d\n", r.rateLimited.Load())
	fmt.Fprintln(&b, "# HELP lab_agent_instances_active Active instances")
	fmt.Fprintln(&b, "# TYPE lab_agent_instances_active gauge")
	fmt.Fprintf(&b, "lab_agent_instances_active %d\n", r.instancesActive.Load())
	fmt.Fprintln(&b, "# HELP lab_agent_instance_starts_total Total successful starts")
	fmt.Fprintln(&b, "# TYPE lab_agent_instance_starts_total counter")
	fmt.Fprintf(&b, "lab_agent_instance_starts_total %d\n", r.instancesStarts.Load())
	fmt.Fprintln(&b, "# HELP lab_agent_instance_stops_total Total successful stops")
	fmt.Fprintln(&b, "# TYPE lab_agent_instance_stops_total counter")
	fmt.Fprintf(&b, "lab_agent_instance_stops_total %d\n", r.instancesStops.Load())

	r.mu.RLock()
	keys := make([]string, 0, len(r.pathCount))
	for k := range r.pathCount {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	latencyBounds := make([]float64, 0, len(r.latencyBuckets))
	for bound := range r.latencyBuckets {
		latencyBounds = append(latencyBounds, bound)
	}
	sort.Float64s(latencyBounds)

	fmt.Fprintln(&b, "# HELP lab_agent_requests_by_path_total Requests by path")
	fmt.Fprintln(&b, "# TYPE lab_agent_requests_by_path_total counter")
	for _, k := range keys {
		fmt.Fprintf(&b, "lab_agent_requests_by_path_total{path=%q} %d\n", k, r.pathCount[k])
	}

	fmt.Fprintln(&b, "# HELP lab_agent_request_duration_seconds Request duration histogram")
	fmt.Fprintln(&b, "# TYPE lab_agent_request_duration_seconds histogram")
	cumulative := uint64(0)
	for _, bound := range latencyBounds {
		cumulative += r.latencyBuckets[bound]
		fmt.Fprintf(&b, "lab_agent_request_duration_seconds_bucket{le=%q} %d\n", trimFloat(bound), cumulative)
	}
	fmt.Fprintf(&b, "lab_agent_request_duration_seconds_bucket{le=\"+Inf\"} %d\n", cumulative+r.latencyInf)
	fmt.Fprintf(&b, "lab_agent_request_duration_seconds_count %d\n", cumulative+r.latencyInf)
	r.mu.RUnlock()
	return b.String()
}

func trimFloat(v float64) string {
	return strings.TrimRight(strings.TrimRight(fmt.Sprintf("%.3f", v), "0"), ".")
}
