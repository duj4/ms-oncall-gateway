package httpapi

import (
	"fmt"
	"sort"
	"strings"
	"sync"
)

type metricKey struct {
	route  string
	result string
}

type requestMetrics struct {
	mu     sync.RWMutex
	counts map[metricKey]uint64
}

func newRequestMetrics() *requestMetrics {
	return &requestMetrics{counts: make(map[metricKey]uint64)}
}

func (m *requestMetrics) increment(route, result string) {
	m.mu.Lock()
	m.counts[metricKey{route: route, result: result}]++
	m.mu.Unlock()
}

func (m *requestMetrics) render() string {
	m.mu.RLock()
	keys := make([]metricKey, 0, len(m.counts))
	for key := range m.counts {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].route == keys[j].route {
			return keys[i].result < keys[j].result
		}
		return keys[i].route < keys[j].route
	})
	counts := make([]uint64, len(keys))
	for i, key := range keys {
		counts[i] = m.counts[key]
	}
	m.mu.RUnlock()

	var output strings.Builder
	output.WriteString("# HELP ms_oncall_gateway_http_requests_total HTTP requests handled by route and bounded result.\n")
	output.WriteString("# TYPE ms_oncall_gateway_http_requests_total counter\n")
	for i, key := range keys {
		fmt.Fprintf(&output, "ms_oncall_gateway_http_requests_total{route=%q,result=%q} %d\n", key.route, key.result, counts[i])
	}
	return output.String()
}
