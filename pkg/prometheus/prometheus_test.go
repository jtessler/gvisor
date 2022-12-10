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

package prometheus

import (
	"fmt"
	"math"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	pb "gvisor.dev/gvisor/pkg/metric/metric_go_proto"
)

// timeNowMu is used to synchronize injection of time.Now.
var timeNowMu sync.Mutex

// at executes a function with the clock returning a given time.
func at(when time.Time, f func()) {
	timeNowMu.Lock()
	defer timeNowMu.Unlock()
	previousFunc := timeNow
	timeNow = func() time.Time { return when }
	defer func() { timeNow = previousFunc }()
	f()
}

// newSnapshotAt creates a new Snapshot with the given timestamp.
func newSnapshotAt(when time.Time) *Snapshot {
	var s *Snapshot
	at(when, func() {
		s = NewSnapshot()
	})
	return s
}

// Helper builder type for metric metadata.
type metricMetadata struct {
	PB     *pb.MetricMetadata
	Fields map[string]string
}

func (m *metricMetadata) clone() *metricMetadata {
	m2 := &metricMetadata{
		PB:     &pb.MetricMetadata{},
		Fields: make(map[string]string, len(m.Fields)),
	}
	proto.Merge(m.PB, m.PB)
	for k, v := range m.Fields {
		m2.Fields[k] = v
	}
	return m2
}

// withField returns a copy of this *metricMetadata with the given field added
// to its metadata.
func (m *metricMetadata) withField(fields ...*pb.MetricMetadata_Field) *metricMetadata {
	m2 := m.clone()
	m2.PB.Fields = make([]*pb.MetricMetadata_Field, 0, len(m.Fields)+len(fields))
	copy(m2.PB.Fields, m.PB.Fields)
	m2.PB.Fields = append(m2.PB.Fields, fields...)
	return m2
}

// metric returns the Metric metadata struct for this metric metadata.
func (m *metricMetadata) metric() *Metric {
	var metricType Type
	switch m.PB.GetType() {
	case pb.MetricMetadata_TYPE_UINT64:
		if m.PB.GetCumulative() {
			metricType = TypeCounter
		} else {
			metricType = TypeGauge
		}
	case pb.MetricMetadata_TYPE_DISTRIBUTION:
		metricType = TypeHistogram
	default:
		panic(fmt.Sprintf("invalid type %v", m.PB.GetType()))
	}
	return &Metric{
		Name: m.PB.GetPrometheusName(),
		Type: metricType,
		Help: m.PB.GetDescription(),
	}
}

// Convenient metric field metadata definitions.
var (
	field1 = &pb.MetricMetadata_Field{
		FieldName:     "field1",
		AllowedValues: []string{"val1a", "val1b"},
	}
	field2 = &pb.MetricMetadata_Field{
		FieldName:     "field2",
		AllowedValues: []string{"val2a", "val2b"},
	}
)

// fieldVal returns a copy of this *metricMetadata with the given field-value
// stored on the side of the metadata. Meant to be used during snapshot data
// construction, where methods like int() make it easy to construct *Data
// structs with field values.
func (m *metricMetadata) fieldVal(field *pb.MetricMetadata_Field, val string) *metricMetadata {
	return m.fieldVals(map[*pb.MetricMetadata_Field]string{field: val})
}

// fieldVals acts like fieldVal but for multiple fields, at the expense of
// having a less convenient function signature.
func (m *metricMetadata) fieldVals(fieldToVal map[*pb.MetricMetadata_Field]string) *metricMetadata {
	m2 := m.clone()
	for field, val := range fieldToVal {
		m2.Fields[field.GetFieldName()] = val
	}
	return m2
}

// labels returns a label key-value map associated with the metricMetadata.
func (m *metricMetadata) labels() map[string]string {
	if len(m.Fields) == 0 {
		return nil
	}
	return m.Fields
}

// int returns a new Data struct with the given value for the current metric.
// If the current metric has fields, all of its fields must accept exactly one
// value, and this value will be used as the value for that field.
// If a field accepts multiple values, the function will panic.
func (m *metricMetadata) int(val int64) *Data {
	data := NewIntData(m.metric(), val)
	data.Labels = m.labels()
	return data
}

// float returns a new Data struct with the given value for the current metric.
// If the current metric has fields, all of its fields must accept exactly one
// value, and this value will be used as the value for that field.
// If a field accepts multiple values, the function will panic.
func (m *metricMetadata) float(val float64) *Data {
	data := NewFloatData(m.metric(), val)
	data.Labels = m.labels()
	return data
}

// float returns a new Data struct with the given value for the current metric.
// If the current metric has fields, all of its fields must accept exactly one
// value, and this value will be used as the value for that field.
// If a field accepts multiple values, the function will panic.
func (m *metricMetadata) dist(samples ...int64) *Data {
	var total int64
	buckets := make([]Bucket, len(m.PB.GetDistributionBucketLowerBounds())+1)
	var bucket *Bucket
	for i, lowerBound := range m.PB.GetDistributionBucketLowerBounds() {
		(&buckets[i]).UpperBound = Number{Int: lowerBound}
	}
	(&buckets[len(buckets)-1]).UpperBound = Number{Float: math.Inf(1)}
	for _, sample := range samples {
		total += sample
		bucket = &buckets[0]
		for i, lowerBound := range m.PB.GetDistributionBucketLowerBounds() {
			if sample >= lowerBound {
				bucket = &buckets[i+1]
			} else {
				break
			}
		}
		bucket.Samples++
	}
	return &Data{
		Metric: m.metric(),
		Labels: m.labels(),
		HistogramValue: &Histogram{
			Total:   Number{Int: total},
			Buckets: buckets,
		},
	}
}

// Convenient metric metadata definitions.
var (
	fooInt = &metricMetadata{
		PB: &pb.MetricMetadata{
			Name:           "fooInt",
			PrometheusName: "foo_int",
			Description:    "An integer about foo",
			Cumulative:     false,
			Units:          pb.MetricMetadata_UNITS_NONE,
			Sync:           true,
			Type:           pb.MetricMetadata_TYPE_UINT64,
		},
	}
	fooCounter = &metricMetadata{
		PB: &pb.MetricMetadata{
			Name:           "fooCounter",
			PrometheusName: "foo_counter",
			Description:    "A counter of foos",
			Cumulative:     true,
			Units:          pb.MetricMetadata_UNITS_NONE,
			Sync:           true,
			Type:           pb.MetricMetadata_TYPE_UINT64,
		},
	}
	fooDist = &metricMetadata{
		PB: &pb.MetricMetadata{
			Name:                          "fooDist",
			PrometheusName:                "foo_dist",
			Description:                   "A distribution about foo",
			Cumulative:                    false,
			Units:                         pb.MetricMetadata_UNITS_NONE,
			Sync:                          true,
			Type:                          pb.MetricMetadata_TYPE_DISTRIBUTION,
			DistributionBucketLowerBounds: []int64{0, 1, 2, 4, 8},
		},
	}
)

// newMetricRegistration returns a new *metricRegistration.
func newMetricRegistration(metricMetadata ...*metricMetadata) *pb.MetricRegistration {
	metadatas := make([]*pb.MetricMetadata, len(metricMetadata))
	for i, mm := range metricMetadata {
		metadatas[i] = mm.PB
	}
	return &pb.MetricRegistration{
		Metrics: metadatas,
	}
}

func TestVerifier(t *testing.T) {
	testStart := time.Now()
	epsilon := func(n int) time.Time {
		return testStart.Add(time.Duration(n) * time.Millisecond)
	}
	for _, test := range []struct {
		Name string

		// At is the time at which the test executes.
		// If unset, `testStart` is assumed.
		At time.Time

		// Registration is the metric registration data.
		Registration *pb.MetricRegistration
		// WantVerifierCreationErr is true if the test expects the
		// creation of the Verifier to fail. All the fields below it
		// are ignored in this case.
		WantVerifierCreationErr bool

		// WantSuccess is a sequence of Snapshots to present to
		// the verifier. The test expects all of them to pass verification.
		// If unset, the test simply presents the WantFail Snapshot.
		// If both WantSuccess and WantFail are unset, the test presents
		// an empty snapshot and expects it to succeed.
		WantSuccess []*Snapshot
		// WantFail is a Snapshot to present to the verifier after all
		// snapshots in WantSuccess have been presented.
		// The test expects this Snapshot to fail verification.
		// If unset, the test does not present any snapshot after
		// having presented the WantSuccess Snapshots.
		WantFail *Snapshot
	}{
		{
			Name: "no metrics, empty snapshot",
		},
		{
			Name:                    "duplicate metric",
			Registration:            newMetricRegistration(fooInt, fooInt),
			WantVerifierCreationErr: true,
		},
		{
			Name:                    "duplicate metric with different field set",
			Registration:            newMetricRegistration(fooInt, fooInt.withField(field1)),
			WantVerifierCreationErr: true,
		},
		{
			Name:                    "duplicate field in metric",
			Registration:            newMetricRegistration(fooInt.withField(field1, field1)),
			WantVerifierCreationErr: true,
		},
		{
			Name: "no field allowed value",
			Registration: newMetricRegistration(fooInt.withField(&pb.MetricMetadata_Field{
				FieldName: "field1",
			})),
			WantVerifierCreationErr: true,
		},
		{
			Name: "duplicate field allowed value",
			Registration: newMetricRegistration(fooInt.withField(&pb.MetricMetadata_Field{
				FieldName:     "field1",
				AllowedValues: []string{"val1", "val1"},
			})),
			WantVerifierCreationErr: true,
		},
		{
			Name: "invalid metric type",
			Registration: newMetricRegistration(&metricMetadata{
				PB: &pb.MetricMetadata{
					Name:           "fooBar",
					PrometheusName: "foo_bar",
					Type:           pb.MetricMetadata_Type(1337),
				}},
			),
			WantVerifierCreationErr: true,
		},
		{
			Name: "empty metric name",
			Registration: newMetricRegistration(&metricMetadata{
				PB: &pb.MetricMetadata{
					PrometheusName: "foo_bar",
					Type:           pb.MetricMetadata_TYPE_UINT64,
				}},
			),
			WantVerifierCreationErr: true,
		},
		{
			Name: "empty Prometheus metric name",
			Registration: newMetricRegistration(&metricMetadata{
				PB: &pb.MetricMetadata{
					Name: "fooBar",
					Type: pb.MetricMetadata_TYPE_UINT64,
				}},
			),
			WantVerifierCreationErr: true,
		},
		{
			Name: "bad Prometheus metric name",
			Registration: newMetricRegistration(&metricMetadata{
				PB: &pb.MetricMetadata{
					Name:           "fooBar",
					PrometheusName: "fooBar",
					Type:           pb.MetricMetadata_TYPE_UINT64,
				}},
			),
			WantVerifierCreationErr: true,
		},
		{
			Name: "bad first Prometheus metric name character",
			Registration: newMetricRegistration(&metricMetadata{
				PB: &pb.MetricMetadata{
					Name:           "fooBar",
					PrometheusName: "_foo_bar",
					Type:           pb.MetricMetadata_TYPE_UINT64,
				}},
			),
			WantVerifierCreationErr: true,
		},
		{
			Name: "no buckets",
			Registration: newMetricRegistration(&metricMetadata{
				PB: &pb.MetricMetadata{
					Name:                          "fooBar",
					PrometheusName:                "foo_bar",
					Type:                          pb.MetricMetadata_TYPE_DISTRIBUTION,
					DistributionBucketLowerBounds: []int64{},
				}},
			),
			WantVerifierCreationErr: true,
		},
		{
			Name: "too many buckets",
			Registration: newMetricRegistration(&metricMetadata{
				PB: &pb.MetricMetadata{
					Name:                          "fooBar",
					PrometheusName:                "foo_bar",
					Type:                          pb.MetricMetadata_TYPE_DISTRIBUTION,
					DistributionBucketLowerBounds: make([]int64, 999),
				}},
			),
			WantVerifierCreationErr: true,
		},
		{
			Name: "successful registration of complex set of metrics",
			Registration: newMetricRegistration(
				fooInt,
				fooCounter.withField(field1, field2),
				fooDist.withField(field2),
			),
		},
		{
			Name: "snapshot time ordering",
			At:   epsilon(0),
			WantSuccess: []*Snapshot{
				newSnapshotAt(epsilon(-3)),
				newSnapshotAt(epsilon(-2)),
				newSnapshotAt(epsilon(-1)),
			},
			WantFail: newSnapshotAt(epsilon(-2)),
		},
		{
			Name: "same snapshot time is ok",
			At:   epsilon(0),
			WantSuccess: []*Snapshot{
				newSnapshotAt(epsilon(-3)),
				newSnapshotAt(epsilon(-2)),
				newSnapshotAt(epsilon(-1)),
				newSnapshotAt(epsilon(-1)),
				newSnapshotAt(epsilon(-1)),
				newSnapshotAt(epsilon(-1)),
				newSnapshotAt(epsilon(0)),
				newSnapshotAt(epsilon(0)),
				newSnapshotAt(epsilon(0)),
				newSnapshotAt(epsilon(0)),
			},
		},
		{
			Name:     "snapshot from the future",
			At:       epsilon(0),
			WantFail: newSnapshotAt(epsilon(1)),
		},
		{
			Name:     "snapshot from the long past",
			At:       testStart,
			WantFail: newSnapshotAt(testStart.Add(-25 * time.Hour)),
		},
		{
			Name:         "simple metric update",
			Registration: newMetricRegistration(fooInt),
			WantSuccess: []*Snapshot{
				newSnapshotAt(epsilon(-1)).Add(
					fooInt.int(2),
				),
			},
		},
		{
			Name:         "simple metric update multiple times",
			Registration: newMetricRegistration(fooInt),
			WantSuccess: []*Snapshot{
				newSnapshotAt(epsilon(-3)).Add(fooInt.int(2)),
				newSnapshotAt(epsilon(-2)).Add(fooInt.int(-1)),
				newSnapshotAt(epsilon(-1)).Add(fooInt.int(4)),
			},
		},
		{
			Name:         "counter can go forwards",
			Registration: newMetricRegistration(fooCounter),
			WantSuccess: []*Snapshot{
				newSnapshotAt(epsilon(-3)).Add(fooCounter.int(1)),
				newSnapshotAt(epsilon(-2)).Add(fooCounter.int(3)),
				newSnapshotAt(epsilon(-1)).Add(fooCounter.int(3)),
			},
		},
		{
			Name:         "counter cannot go backwards",
			Registration: newMetricRegistration(fooCounter),
			WantSuccess: []*Snapshot{
				newSnapshotAt(epsilon(-3)).Add(fooCounter.int(1)),
				newSnapshotAt(epsilon(-2)).Add(fooCounter.int(3)),
			},
			WantFail: newSnapshotAt(epsilon(-1)).Add(fooCounter.int(2)),
		},
		{
			Name:         "counter cannot change type",
			Registration: newMetricRegistration(fooCounter),
			WantSuccess: []*Snapshot{
				newSnapshotAt(epsilon(-3)).Add(fooCounter.int(1)),
				newSnapshotAt(epsilon(-2)).Add(fooCounter.int(3)),
			},
			WantFail: newSnapshotAt(epsilon(-1)).Add(fooCounter.float(4)),
		},
		{
			Name:         "update for unknown metric",
			Registration: newMetricRegistration(fooInt),
			WantFail:     newSnapshotAt(epsilon(-1)).Add(fooCounter.int(2)),
		},
		{
			Name:         "update for mismatching metric definition: type",
			Registration: newMetricRegistration(fooInt),
			WantFail: newSnapshotAt(epsilon(-1)).Add(
				(&metricMetadata{PB: &pb.MetricMetadata{
					PrometheusName: fooInt.PB.GetPrometheusName(),
					Type:           pb.MetricMetadata_TYPE_DISTRIBUTION,
					Description:    fooInt.PB.GetDescription(),
				}}).int(2),
			),
		},
		{
			Name:         "update for mismatching metric definition: name",
			Registration: newMetricRegistration(fooInt),
			WantFail: newSnapshotAt(epsilon(-1)).Add(
				(&metricMetadata{PB: &pb.MetricMetadata{
					PrometheusName: "not_foo_int",
					Type:           fooInt.PB.GetType(),
					Description:    fooInt.PB.GetDescription(),
				}}).int(2),
			),
		},
		{
			Name:         "update for mismatching metric definition: description",
			Registration: newMetricRegistration(fooInt),
			WantFail: newSnapshotAt(epsilon(-1)).Add(
				(&metricMetadata{PB: &pb.MetricMetadata{
					PrometheusName: fooInt.PB.GetPrometheusName(),
					Type:           fooInt.PB.GetType(),
					Description:    "not fooInt's description",
				}}).int(2),
			),
		},
		{
			Name:         "update with no fields for metric with fields",
			Registration: newMetricRegistration(fooInt.withField(field1)),
			WantFail:     newSnapshotAt(epsilon(-1)).Add(fooInt.int(2)),
		},
		{
			Name:         "update with fields for metric without fields",
			Registration: newMetricRegistration(fooInt),
			WantFail: newSnapshotAt(epsilon(-1)).Add(
				fooInt.fieldVal(field1, "val1a").int(2),
			),
		},
		{
			Name:         "update with invalid field value",
			Registration: newMetricRegistration(fooInt.withField(field1)),
			WantFail: newSnapshotAt(epsilon(-1)).Add(
				fooInt.fieldVal(field1, "not_val1a").int(2),
			),
		},
		{
			Name:         "update with valid field value for wrong field",
			Registration: newMetricRegistration(fooInt.withField(field1)),
			WantFail: newSnapshotAt(epsilon(-1)).Add(
				fooInt.fieldVal(field2, "val1a").int(2),
			),
		},
		{
			Name:         "update with valid field values provided twice",
			Registration: newMetricRegistration(fooInt.withField(field1)),
			WantFail: newSnapshotAt(epsilon(-1)).Add(
				fooInt.fieldVal(field1, "val1a").int(2),
				fooInt.fieldVal(field1, "val1a").int(2),
			),
		},
		{
			Name:         "update with valid field value",
			Registration: newMetricRegistration(fooInt.withField(field1)),
			WantSuccess: []*Snapshot{
				newSnapshotAt(epsilon(-1)).Add(
					fooInt.fieldVal(field1, "val1a").int(7),
					fooInt.fieldVal(field1, "val1b").int(2),
				),
			},
		},
		{
			Name:         "update with multiple valid field value",
			Registration: newMetricRegistration(fooCounter.withField(field1, field2)),
			WantSuccess: []*Snapshot{
				newSnapshotAt(epsilon(-1)).Add(
					fooCounter.fieldVals(map[*pb.MetricMetadata_Field]string{
						field1: "val1a",
						field2: "val2a",
					}).int(3),
					fooCounter.fieldVals(map[*pb.MetricMetadata_Field]string{
						field1: "val1b",
						field2: "val2a",
					}).int(2),
					fooCounter.fieldVals(map[*pb.MetricMetadata_Field]string{
						field1: "val1a",
						field2: "val2b",
					}).int(1),
					fooCounter.fieldVals(map[*pb.MetricMetadata_Field]string{
						field1: "val1b",
						field2: "val2b",
					}).int(4),
				),
			},
		},
		{
			Name:         "update with multiple valid field values but duplicated",
			Registration: newMetricRegistration(fooCounter.withField(field1, field2)),
			WantFail: newSnapshotAt(epsilon(-1)).Add(
				fooCounter.fieldVals(map[*pb.MetricMetadata_Field]string{
					field1: "val1b",
					field2: "val2b",
				}).int(4),
				fooCounter.fieldVals(map[*pb.MetricMetadata_Field]string{
					field1: "val1b",
					field2: "val2b",
				}).int(4),
			),
		},
		{
			Name: "update with same valid field values across two metrics",
			Registration: newMetricRegistration(
				fooInt.withField(field1, field2),
				fooCounter.withField(field1, field2),
			),
			WantSuccess: []*Snapshot{
				newSnapshotAt(epsilon(-1)).Add(
					fooInt.fieldVals(map[*pb.MetricMetadata_Field]string{
						field1: "val1a",
						field2: "val2a",
					}).int(3),
					fooCounter.fieldVals(map[*pb.MetricMetadata_Field]string{
						field1: "val1a",
						field2: "val2a",
					}).int(3),
				),
			},
		},
		{
			Name:         "update with multiple value types",
			Registration: newMetricRegistration(fooInt),
			WantFail: newSnapshotAt(epsilon(-1)).Add(
				&Data{
					Metric: fooInt.metric(),
					Number: &Number{Int: 2},
					HistogramValue: &Histogram{
						Total: Number{Int: 5},
						Buckets: []Bucket{
							{UpperBound: Number{Int: 0}, Samples: 1},
							{UpperBound: Number{Int: 1}, Samples: 1},
						},
					},
				},
			),
		},
		{
			Name:         "integer metric gets float value",
			Registration: newMetricRegistration(fooInt),
			WantFail:     newSnapshotAt(epsilon(-1)).Add(fooInt.float(2.5)),
		},
		{
			Name:         "metric gets no value",
			Registration: newMetricRegistration(fooInt),
			WantFail:     newSnapshotAt(epsilon(-1)).Add(&Data{Metric: fooInt.metric()}),
		},
		{
			Name:         "distribution gets integer value",
			Registration: newMetricRegistration(fooDist),
			WantFail: newSnapshotAt(epsilon(-1)).Add(
				fooDist.int(2),
			),
		},
		{
			Name:         "successful distribution",
			Registration: newMetricRegistration(fooDist),
			WantSuccess: []*Snapshot{
				newSnapshotAt(epsilon(-1)).Add(
					fooDist.dist(1, 2, 3, 4, 5, 6),
				),
			},
		},
		{
			Name:         "distribution updates",
			Registration: newMetricRegistration(fooDist),
			WantSuccess: []*Snapshot{
				newSnapshotAt(epsilon(-2)).Add(
					fooDist.dist(1, 2, 3, 4, 5, 6),
				),
				newSnapshotAt(epsilon(-1)).Add(
					fooDist.dist(0, 1, 1, 2, 2, 3, 4, 5, 5, 6, 7, 8, 9, 25),
				),
			},
		},
		{
			Name:         "distribution updates with fields",
			Registration: newMetricRegistration(fooDist.withField(field1)),
			WantSuccess: []*Snapshot{
				newSnapshotAt(epsilon(-2)).Add(
					fooDist.fieldVal(field1, "val1a").dist(1, 2, 3, 4, 5, 6),
				),
				newSnapshotAt(epsilon(-1)).Add(
					fooDist.fieldVal(field1, "val1a").dist(0, 1, 1, 2, 2, 3, 4, 5, 5, 6, 7, 8, 9, 25),
				),
			},
		},
		{
			Name:         "distribution cannot have number of samples regress",
			Registration: newMetricRegistration(fooDist),
			WantSuccess: []*Snapshot{
				newSnapshotAt(epsilon(-3)).Add(
					fooDist.dist(1, 2, 3, 4, 5, 6),
				),
				newSnapshotAt(epsilon(-2)).Add(
					fooDist.dist(0, 1, 1, 2, 2, 3, 4, 5, 5, 6, 7, 8, 9, 25),
				),
			},
			WantFail: newSnapshotAt(epsilon(-1)).Add(
				fooDist.dist(0, 1, 2, 2, 3, 4, 5, 5, 6, 7, 8, 9),
			),
		},
		{
			Name:         "distribution with zero samples",
			Registration: newMetricRegistration(fooDist),
			WantSuccess: []*Snapshot{newSnapshotAt(epsilon(-1)).Add(
				&Data{
					Metric: fooDist.metric(),
					HistogramValue: &Histogram{
						Buckets: []Bucket{
							{UpperBound: Number{Int: 0}, Samples: 0},
							{UpperBound: Number{Int: 1}, Samples: 0},
							{UpperBound: Number{Int: 2}, Samples: 0},
							{UpperBound: Number{Int: 4}, Samples: 0},
							{UpperBound: Number{Int: 8}, Samples: 0},
							{UpperBound: Number{Float: math.Inf(1)}, Samples: 0},
						},
					},
				},
			)},
		},
		{
			Name:         "distribution with manual samples",
			Registration: newMetricRegistration(fooDist),
			WantSuccess: []*Snapshot{newSnapshotAt(epsilon(-1)).Add(
				&Data{
					Metric: fooDist.metric(),
					HistogramValue: &Histogram{
						Total: Number{Int: 10},
						Buckets: []Bucket{
							{UpperBound: Number{Int: 0}, Samples: 2},
							{UpperBound: Number{Int: 1}, Samples: 1},
							{UpperBound: Number{Int: 2}, Samples: 3},
							{UpperBound: Number{Int: 4}, Samples: 1},
							{UpperBound: Number{Int: 8}, Samples: 4},
							{UpperBound: Number{Float: math.Inf(1)}, Samples: 1},
						},
					},
				},
			)},
		},
		{
			Name:         "distribution gets bad number of buckets",
			Registration: newMetricRegistration(fooDist),
			WantFail: newSnapshotAt(epsilon(-1)).Add(
				&Data{
					Metric: fooDist.metric(),
					HistogramValue: &Histogram{
						Total: Number{Int: 10},
						Buckets: []Bucket{
							{UpperBound: Number{Int: 0}, Samples: 2},
							{UpperBound: Number{Int: 1}, Samples: 1},
							{UpperBound: Number{Int: 2}, Samples: 3},
							// Missing: {UpperBound: Number{Int: 4}, Samples: 1},
							{UpperBound: Number{Int: 8}, Samples: 4},
							{UpperBound: Number{Float: math.Inf(1)}, Samples: 1},
						},
					},
				},
			),
		},
		{
			Name:         "distribution gets unexpected bucket boundary",
			Registration: newMetricRegistration(fooDist),
			WantFail: newSnapshotAt(epsilon(-1)).Add(
				&Data{
					Metric: fooDist.metric(),
					HistogramValue: &Histogram{
						Total: Number{Int: 10},
						Buckets: []Bucket{
							{UpperBound: Number{Int: 0}, Samples: 2},
							{UpperBound: Number{Int: 1}, Samples: 1},
							{UpperBound: Number{Int: 3 /* Should be 2 */}, Samples: 3},
							{UpperBound: Number{Int: 4}, Samples: 1},
							{UpperBound: Number{Int: 8}, Samples: 4},
							{UpperBound: Number{Float: math.Inf(1)}, Samples: 1},
						},
					},
				},
			),
		},
		{
			Name:         "distribution gets unexpected last bucket boundary",
			Registration: newMetricRegistration(fooDist),
			WantFail: newSnapshotAt(epsilon(-1)).Add(
				&Data{
					Metric: fooDist.metric(),
					HistogramValue: &Histogram{
						Total: Number{Int: 10},
						Buckets: []Bucket{
							{UpperBound: Number{Int: 0}, Samples: 2},
							{UpperBound: Number{Int: 1}, Samples: 1},
							{UpperBound: Number{Int: 2}, Samples: 3},
							{UpperBound: Number{Int: 4}, Samples: 1},
							{UpperBound: Number{Int: 8}, Samples: 4},
							{
								UpperBound: Number{Float: math.Inf(-1) /* Should be +inf */},
								Samples:    1,
							},
						},
					},
				},
			),
		},
		{
			Name: "worked example",
			Registration: newMetricRegistration(
				fooInt,
				fooDist.withField(field1),
				fooCounter.withField(field1, field2),
			),
			WantSuccess: []*Snapshot{
				// Empty snapshot.
				newSnapshotAt(epsilon(-6)),
				// Simple snapshot.
				newSnapshotAt(epsilon(-5)).Add(
					fooInt.int(3),
					fooDist.fieldVal(field1, "val1a").dist(1, 2, 3, 4, 5, 6),
					fooDist.fieldVal(field1, "val1b").dist(-1, -8, 100),
					fooCounter.fieldVals(map[*pb.MetricMetadata_Field]string{
						field1: "val1a",
						field2: "val2a",
					}).int(6),
					fooCounter.fieldVals(map[*pb.MetricMetadata_Field]string{
						field1: "val1b",
						field2: "val2a",
					}).int(3),
				),
				// And another.
				newSnapshotAt(epsilon(-4)).Add(
					fooInt.int(1),
					fooDist.fieldVal(field1, "val1a").dist(1, 2, 3, 4, 5, 6, 7),
					fooDist.fieldVal(field1, "val1b").dist(-1, -8, 100, 42),
					fooCounter.fieldVals(map[*pb.MetricMetadata_Field]string{
						field1: "val1a",
						field2: "val2a",
					}).int(6),
					fooCounter.fieldVals(map[*pb.MetricMetadata_Field]string{
						field1: "val1b",
						field2: "val2a",
					}).int(4),
				),
				// And another one, partial this time.
				newSnapshotAt(epsilon(-3)).Add(
					fooDist.fieldVal(field1, "val1b").dist(-1, -8, 100, 42, 1337),
					fooCounter.fieldVals(map[*pb.MetricMetadata_Field]string{
						field1: "val1a",
						field2: "val2a",
					}).int(6),
				),
				// An empty one.
				newSnapshotAt(epsilon(-2)),
				// Another empty one at the same timestamp.
				newSnapshotAt(epsilon(-1)),
				// Another full one which doesn't change any value.
				newSnapshotAt(epsilon(0)).Add(
					fooInt.int(1),
					fooDist.fieldVal(field1, "val1a").dist(1, 2, 3, 4, 5, 6, 7),
					fooDist.fieldVal(field1, "val1b").dist(-1, -8, 100, 42, 1337),
					fooCounter.fieldVals(map[*pb.MetricMetadata_Field]string{
						field1: "val1a",
						field2: "val2a",
					}).int(6),
					fooCounter.fieldVals(map[*pb.MetricMetadata_Field]string{
						field1: "val1b",
						field2: "val2a",
					}).int(4),
				),
			},
		},
	} {
		t.Run(test.Name, func(t *testing.T) {
			testTime := test.At
			if testTime.IsZero() {
				testTime = testStart
			}
			at(testTime, func() {
				t.Logf("Test is running with simulated time: %v", testTime)
				verifier, err := NewVerifier(test.Registration)
				if err != nil && !test.WantVerifierCreationErr {
					t.Fatalf("unexpected verifier creation error: %v", err)
				} else if err == nil && test.WantVerifierCreationErr {
					t.Fatal("verifier creation unexpectedly succeeded")
				} else if err != nil && test.WantVerifierCreationErr {
					// If the verifier didn't successfully initialize, don't go further.
					t.Logf("Verifier creation failed (as expected by this test): %v", err)
					return
				}
				if len(test.WantSuccess) == 0 && test.WantFail == nil {
					if err = verifier.Verify(NewSnapshot()); err != nil {
						t.Errorf("empty snapshot failed verification: %v", err)
					}
				} else {
					for i, snapshot := range test.WantSuccess {
						if err = verifier.Verify(snapshot); err != nil {
							t.Fatalf("snapshot WantSuccess[%d] failed verification: %v", i, err)
						}
					}
					if test.WantFail != nil {
						if err = verifier.Verify(test.WantFail); err == nil {
							t.Error("WantFail snapshot unexpectedly succeeded verification")
						} else {
							t.Logf("WantFail snapshot failed verification (as expected by this test): %v", err)
						}
					}
				}
			})
		})
	}
}
