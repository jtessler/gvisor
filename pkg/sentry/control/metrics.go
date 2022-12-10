// Copyright 2022 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package control

import (
	"gvisor.dev/gvisor/pkg/metric"
	pb "gvisor.dev/gvisor/pkg/metric/metric_go_proto"
	"gvisor.dev/gvisor/pkg/prometheus"
)

// Metrics includes metrics-related RPC stubs.
type Metrics struct{}

// GetRegisteredMetricsOpts contains metric registration query options.
type GetRegisteredMetricsOpts struct{}

// MetricsRegistrationResponse contains metric registration data.
type MetricsRegistrationResponse struct {
	RegisteredMetrics *pb.MetricRegistration
}

// GetRegisteredMetrics returns the registered metrics.
// This should only be called during Sentry boot, before any container starts,
// as the purpose of metric registration data is to ensure the integrity of
// instrumentation data from the Sentry after untrusted workloads have started.
func (u *Metrics) GetRegisteredMetrics(_ *GetRegisteredMetricsOpts, out *MetricsRegistrationResponse) error {
	registration, err := metric.GetMetricRegistration()
	if err != nil {
		return err
	}
	out.RegisteredMetrics = registration
	return nil
}

// MetricsExportOpts contains metric exporting options.
type MetricsExportOpts struct{}

// MetricsExportData contains data for all metrics being exported.
type MetricsExportData struct {
	Snapshot *prometheus.Snapshot `json:"snapshot"`
}

// Export export metrics data into MetricsExportData.
func (u *Metrics) Export(_ *MetricsExportOpts, out *MetricsExportData) error {
	out.Snapshot = metric.GetSnapshot()
	return nil
}
