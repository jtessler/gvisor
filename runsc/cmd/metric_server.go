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

package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/google/subcommands"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/prometheus"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/runsc/cmd/util"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/container"
	"gvisor.dev/gvisor/runsc/flag"
	"gvisor.dev/gvisor/runsc/sandbox"
)

const (
	// verifyLoopInterval is the interval at which we check whether there are any sandboxes we need
	// to serve metrics for. If there are none, the server exits.
	verifyLoopInterval = 5 * time.Second

	// firstSandboxTimeout is the time that the server will stay up waiting for its first sandbox
	// to register. If no sandbox registers within this time, it will exit with a failure.
	// If a sandbox does register within this time, the server will exit after all sandboxes have
	// unregistered, and the verify loop has run (see verifyLoopInterval).
	firstSandboxTimeout = 2 * time.Minute

	// keepAliveTimeout  is the time that the server will stay up waiting for new sandboxes to start.
	// If no sandbox does register within this time, and the server isn't serving data for any other
	// sandbox, it will exit.
	keepAliveTimeout = 2 * time.Minute

	// httpTimeout is the timeout used for all connect/read/write operations of the HTTP server.
	httpTimeout = 1 * time.Minute

	// metricsExportTimeout is the maximum amount of time that the metrics export process should take.
	metricsExportTimeout = 30 * time.Second

	// metricsExportPerSandboxTimeout is the maximum amount of time that we wait on any individual
	// sandbox when exporting its metrics.
	metricsExportPerSandboxTimeout = 8 * time.Second

	// exportParallelGoroutines is the maximum number of goroutines spawned during metrics export.
	exportParallelGoroutines = 8
)

// Prometheus label names.
const (
	iterationIDLabel = "iterationid"
)

// servedSandbox is a sandbox that we serve metrics from.
// A single metrics server will export data about multiple sandboxes.
type servedSandbox struct {
	rootContainerID container.FullID
	rootDir         string
	extraLabels     map[string]string

	// mu protects the fields below.
	mu sync.Mutex

	// sandbox is the sandbox being monitored.
	// Once set, it is immutable.
	sandbox *sandbox.Sandbox

	// verifier allows verifying the data integrity of the metrics we get from this sandbox.
	// It is not initialized during sandbox registration, but rather upon first metrics access
	// to the sandbox. Metric registration data is loaded from disk, within the Container data.
	// The server needs to load this registration data before any data from this sandbox is
	// served to HTTP clients. If there is no metric registration data within the Container
	// data, then metrics were not requested for this sandbox, and this servedSandbox should
	// be deleted from the server.
	// Once set, it is immutable.
	verifier *prometheus.Verifier
}

// load loads the sandbox being monitored and initializes its metric verifier.
// If it returns an error other than container.ErrStateFileLocked, the sandbox is either
// non-existent, or has not requested instrumentation to be enabled, or does not have
// valid metric registration data. In any of these cases, the sandbox should be removed
// from this metrics server.
func (s *servedSandbox) load() (*sandbox.Sandbox, *prometheus.Verifier, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sandbox == nil {
		cont, err := container.Load(s.rootDir, s.rootContainerID, container.LoadOpts{
			Exact:         true,
			SkipCheck:     true,
			TryLock:       container.TryAcquire,
			RootContainer: true,
		})
		if err != nil {
			return nil, nil, err
		}
		// Update label data as read from the state file, in case we got fed wrong versions
		// during registration. Do not store empty labels.
		authoritativeLabels := cont.Sandbox.PrometheusLabels()
		for _, label := range []string{sandbox.SandboxIDLabel, sandbox.PodNameLabel, sandbox.NamespaceLabel} {
			s.extraLabels[label] = authoritativeLabels[label]
			if s.extraLabels[label] == "" {
				delete(s.extraLabels, label)
			}
		}
		s.sandbox = cont.Sandbox
	}
	if s.verifier == nil {
		registeredMetrics, err := s.sandbox.GetRegisteredMetrics()
		if err != nil {
			return nil, nil, err
		}
		verifier, err := prometheus.NewVerifier(registeredMetrics)
		if err != nil {
			return nil, nil, err
		}
		s.verifier = verifier
	}
	return s.sandbox, s.verifier, nil
}

// queryMetrics queries the sandbox for metrics data.
func queryMetrics(ctx context.Context, sand *sandbox.Sandbox, verifier *prometheus.Verifier) (*prometheus.Snapshot, error) {
	ch := make(chan struct {
		snapshot *prometheus.Snapshot
		err      error
	}, 1)
	defer close(ch)
	go func() {
		snapshot, err := sand.ExportMetrics()
		select {
		case ch <- struct {
			snapshot *prometheus.Snapshot
			err      error
		}{snapshot, err}:
		default:
		}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case ret := <-ch:
		if ret.err != nil {
			return nil, ret.err
		}
		if err := verifier.Verify(ret.snapshot); err != nil {
			return nil, err
		}
		return ret.snapshot, nil
	}
}

// MetricServer implements subcommands.Command for the "metric-server" command.
type MetricServer struct {
	rootDir        string
	exporterPrefix string
	persistent     bool
	startTime      time.Time
	rand           *rand.Rand
	srv            http.Server

	// firstSandboxDeadline is the time at which the server will die if it has never gotten any
	// sandbox registration by then. Ignored if `persistent` is true.
	// Takes precedence over `keepAliveDeadline` if the server has not yet served any sandbox.
	firstSandboxDeadline time.Time

	// Size of the map of written metrics during the last /metrics export. Initially zero.
	// Used to efficiently reallocate a map of the right size during the next export.
	lastMetricsWrittenSize atomicbitops.Uint32

	// mu protects the fields below.
	mu sync.Mutex

	// udsPath is a path to a Unix Domain Socket file on which the server is bound and which it owns.
	// This socket file will be deleted on server shutdown.
	// This field is not set if binding to a network port, or when the UDS already existed prior to
	// being bound by us (i.e. its ownership isn't ours), such that it isn't deleted in this case.
	// The field is unset once the file is succesfully removed.
	udsPath string

	// sandboxes is the list of sandboxes we serve metrics for.
	// The server will shut down a few seconds after this list becomes empty.
	sandboxes map[string]*servedSandbox

	// keepAliveDeadline is the time at which the server will die if it hasn't received any new
	// sandbox metric registration by then. Ignored if `persistent` is true.
	// Ignored if set to the zero time.
	// Takes precedence over `firstSandboxDeadline` if the server has served any sandbox in the past.
	keepAliveDeadline time.Time

	// numSandboxes counts the number of sandboxes that have ever been registered on this server.
	// Used to distinguish between the case where this metrics serve has sat there doing nothing
	// because no sandbox ever registered against it (which is unexpected), vs the case where it has
	// done a good job serving sandbox metrics and it's time for it to gracefully die as there are no
	// more sandboxes to serve.
	// Also exported as a metric of total number of sandboxes started.
	numSandboxes int64

	// shuttingDown is flipped to true when the server shutdown process has started.
	// Used to deal with race conditions where a sandbox is trying to register after the server has
	// already started to go to sleep.
	shuttingDown bool
}

// Name implements subcommands.Command.Name.
func (*MetricServer) Name() string {
	return "metric-server"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*MetricServer) Synopsis() string {
	return "implements Prometheus metrics HTTP endpoint"
}

// Usage implements subcommands.Command.Usage.
func (*MetricServer) Usage() string {
	return `-root=<root dir> -metric-server=<addr> -metric-exporter-prefix=<prefix_> metric-server`
}

// SetFlags implements subcommands.Command.SetFlags.
func (m *MetricServer) SetFlags(f *flag.FlagSet) {}

func (m *MetricServer) extendKeepAliveLocked() {
	if !m.shuttingDown && len(m.sandboxes) == 0 {
		m.keepAliveDeadline = time.Now().Add(keepAliveTimeout)
		log.Infof("Server no longer serving any sandbox metrics. Will stay alive until at least %v.", m.keepAliveDeadline)
	}
}

// purgeSandboxesLocked removes sandboxes that are no longer running from m.sandboxes.
// Preconditions: m.mu is locked.
func (m *MetricServer) purgeSandboxesLocked() {
	if m.shuttingDown {
		// Do nothing to avoid log spam.
		return
	}
	containers, err := container.List(m.rootDir)
	if err != nil {
		log.Warningf("Cannot list containers in root directory %s, it has likely gone away: %v.", m.rootDir, err)
		return
	}
	for sandboxID, sandbox := range m.sandboxes {
		found := false
		for _, cid := range containers {
			if cid.SandboxID == sandboxID {
				found = true
				break
			}
		}
		if !found {
			log.Warningf("Sandbox %s no longer exists but did not explicitly unregister. Removing it.", sandboxID)
			delete(m.sandboxes, sandboxID)
		} else if _, _, err := sandbox.load(); err != nil && err != container.ErrStateFileLocked {
			log.Warningf("Sandbox %s cannot be loaded, deleting it: %v", sandboxID, err)
			delete(m.sandboxes, sandboxID)
		}
	}
}

// shutdownLocked shuts down the server. It assumes mu is held.
func (m *MetricServer) shutdownLocked(ctx context.Context) {
	log.Infof("Server shutting down.")
	m.shuttingDown = true
	if m.udsPath != "" {
		if err := os.Remove(m.udsPath); err != nil {
			log.Warningf("Cannot remove UDS at %s: %v", m.udsPath, err)
		} else {
			m.udsPath = ""
		}
	}
	m.srv.Shutdown(ctx)
}

// httpResult is returned by HTTP handlers.
type httpResult struct {
	code int
	err  error
}

// httpOK is the "everything went fine" HTTP result.
var httpOK = httpResult{code: http.StatusOK}

// serveIndex serves the index page.
func (m *MetricServer) serveIndex(w http.ResponseWriter, req *http.Request) httpResult {
	if req.URL.Path != "/" {
		return httpResult{http.StatusNotFound, errors.New("path not found")}
	}
	fmt.Fprintf(w, "<html><head><title>runsc metrics</title></head><body>")
	fmt.Fprintf(w, "<p>You have reached the runsc metrics server page!</p>")
	fmt.Fprintf(w, `<p>To see actual metric data, head over to <a href="/metrics">/metrics</a>.</p>`)
	fmt.Fprintf(w, "</body></html>")
	return httpOK
}

// Metrics generated by the metrics server itself.
var (
	sandboxPresenceMetric = prometheus.Metric{
		Name: "sandbox_presence",
		Type: prometheus.TypeGauge,
		Help: "Boolean metric set to 1 for each registered sandbox.",
	}
	sandboxRunningMetric = prometheus.Metric{
		Name: "sandbox_running",
		Type: prometheus.TypeGauge,
		Help: "Boolean metric set to 1 for each running sandbox.",
	}
	numRunningSandboxesMetric = prometheus.Metric{
		Name: "num_sandboxes_running",
		Type: prometheus.TypeGauge,
		Help: "Number of sandboxes running at present.",
	}
	numCannotExportSandboxesMetric = prometheus.Metric{
		Name: "num_sandboxes_broken_metrics",
		Type: prometheus.TypeGauge,
		Help: "Number of sandboxes from which we cannot export metrics.",
	}
	numTotalSandboxesMetric = prometheus.Metric{
		Name: "num_sandboxes_total",
		Type: prometheus.TypeCounter,
		Help: "Counter of sandboxes that have ever been started.",
	}
	processStartTimeMetric = prometheus.Metric{
		Name: "process_start_time_seconds",
		Type: prometheus.TypeGauge,
		Help: "Unix timestamp at which the process started. Used by Prometheus for counter resets.",
	}
)

// serveMetrics serves metrics requests.
func (m *MetricServer) serveMetrics(w http.ResponseWriter, req *http.Request) httpResult {
	ctx, ctxCancel := context.WithTimeout(req.Context(), metricsExportTimeout)
	defer ctxCancel()
	m.mu.Lock()
	m.purgeSandboxesLocked()
	m.extendKeepAliveLocked()

	numGoroutines := exportParallelGoroutines
	numSandboxes := len(m.sandboxes)
	if numSandboxes < numGoroutines {
		numGoroutines = numSandboxes
	}

	// First, load all the sandboxes in parallel. We need to do this while m.mu is held.
	loadSandboxCh := make(chan *servedSandbox, numSandboxes)
	type sandboxLoadResult struct {
		served   *servedSandbox
		sandbox  *sandbox.Sandbox
		verifier *prometheus.Verifier
		err      error
	}
	loadedSandboxesCh := make(chan sandboxLoadResult, numSandboxes)
	loadedSandboxes := make([]sandboxLoadResult, 0, numSandboxes)
	for i := 0; i < numGoroutines; i++ {
		go func() {
			for served := range loadSandboxCh {
				sand, verifier, err := served.load()
				loadedSandboxesCh <- sandboxLoadResult{served, sand, verifier, err}
			}
		}()
	}
	for _, sandbox := range m.sandboxes {
		loadSandboxCh <- sandbox
	}
	close(loadSandboxCh)
	for i := 0; i < numSandboxes; i++ {
		loadedSandboxes = append(loadedSandboxes, <-loadedSandboxesCh)
	}
	close(loadedSandboxesCh)
	m.mu.Unlock()

	// Now iterate over all sandboxes.
	// Important: This must be done in random order.
	// A malicious/compromised sandbox may decide to stall when being asked for metrics.
	// If at least `numGoroutines` sandboxes do this, this will starve other sandboxes
	// from having their metrics exported, because all the goroutines will be stuck on
	// the stalled sandboxes.
	// One way to completely avoid this would be to spawn one goroutine per
	// sandbox, but this can amount to ~hundreds of goroutines, which is not desirable
	// for the metrics server.
	// Another way would be to have a very strict timeout on each sandbox's export
	// process, but in some cases a busy sandbox will take more than a decisecond
	// or so to export its data, so this would miss some data from legitimate (but
	// slow) sandboxes.
	// Instead, we take a middle-of-the-road approach: we use a timeout that's not
	// too strict but still ensures we make forward progress away from stalled
	// sandboxes, and we also iterate across sandboxes in a different random order at
	// each export. This ensures that all sandboxes eventually get a fair chance of
	// being part of the "first `numGoroutines` sandboxes in line" to get their
	// metric data loaded, such that a client repeatedly scraping metrics will
	// eventually get data from each sandbox.

	// Used to prevent goroutines from accessing the shared variables below.
	var metricsMu sync.Mutex

	// Meta-metrics keep track of metrics to export about the metrics server itself.
	type metaMetrics struct {
		numRunningSandboxes      int64
		numCannotExportSandboxes int64
	}
	meta := metaMetrics{}                   // Protected by metricsMu.
	selfMetrics := prometheus.NewSnapshot() // Protected by metricsMu.

	ctxDeadline, ok := ctx.Deadline()
	if !ok {
		panic("context had no deadline, this should never happen as it was created with a timeout")
	}
	exportStartTime := time.Now()
	requestTimeLeft := ctxDeadline.Sub(exportStartTime)
	perSandboxTime := requestTimeLeft / time.Duration(numSandboxes)
	if perSandboxTime < metricsExportPerSandboxTimeout {
		perSandboxTime = metricsExportPerSandboxTimeout
	}
	loadedSandboxCh := make(chan sandboxLoadResult, numSandboxes)
	type snapshotAndOptions struct {
		snapshot *prometheus.Snapshot
		options  prometheus.SnapshotExportOptions
	}
	snapshotCh := make(chan snapshotAndOptions, numSandboxes)
	var wg sync.WaitGroup
	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(metricsMu *sync.Mutex, meta *metaMetrics, selfMetrics *prometheus.Snapshot) {
			defer wg.Done()
			for s := range loadedSandboxCh {
				served, sand, verifier, err := s.served, s.sandbox, s.verifier, s.err
				isRunning := false
				var snapshot *prometheus.Snapshot
				if err == nil {
					queryCtx, queryCtxCancel := context.WithTimeout(ctx, perSandboxTime)
					snapshot, err = queryMetrics(queryCtx, sand, verifier)
					queryCtxCancel()
					isRunning = sand.IsRunning()
				}
				func() {
					metricsMu.Lock()
					defer metricsMu.Unlock()
					selfMetrics.Add(prometheus.LabeledIntData(&sandboxPresenceMetric, served.extraLabels, 1))
					sandboxRunning := int64(0)
					if isRunning {
						sandboxRunning = 1
					}
					selfMetrics.Add(prometheus.LabeledIntData(&sandboxRunningMetric, served.extraLabels, sandboxRunning))
					if err != nil && !isRunning {
						// The sandbox either hasn't started running yet, or it ran and has gone away between the
						// start of the function and now. It is normal that metrics are not exported for this
						// sandbox in this case, so do not report this as an error.
						return
					}
					if err != nil {
						meta.numRunningSandboxes++
						meta.numCannotExportSandboxes++
						log.Warningf("Could not export metrics from sandbox %s: %v", served.rootContainerID.SandboxID, err)
						return
					}
					meta.numRunningSandboxes++
					snapshotCh <- snapshotAndOptions{
						snapshot: snapshot,
						options: prometheus.SnapshotExportOptions{
							ExporterPrefix: m.exporterPrefix,
							ExtraLabels:    served.extraLabels,
						},
					}
				}()
			}
		}(&metricsMu, &meta, selfMetrics)
	}
	// Feed the channel in random order:
	for _, sandboxIndex := range rand.Perm(len(loadedSandboxes)) {
		loadedSandboxCh <- loadedSandboxes[sandboxIndex]
	}
	close(loadedSandboxCh)

	// Meanwhile, build the map of all snapshots we will be rendering.
	snapshotsToOptions := make(map[*prometheus.Snapshot]prometheus.SnapshotExportOptions, numSandboxes+2)
	snapshotsToOptions[selfMetrics] = prometheus.SnapshotExportOptions{
		ExporterPrefix: fmt.Sprintf("%smeta_", m.exporterPrefix),
	}
	processMetrics := prometheus.NewSnapshot()
	processMetrics.Add(prometheus.NewFloatData(&processStartTimeMetric, float64(m.startTime.Unix())+(float64(m.startTime.Nanosecond())/1e9)))
	snapshotsToOptions[processMetrics] = prometheus.SnapshotExportOptions{
		// These metrics must be written without any prefix.
	}

	// Aggregate all the snapshots from the sandboxes.
	wg.Wait()
	close(snapshotCh)
	for snapshotAndOptions := range snapshotCh {
		snapshotsToOptions[snapshotAndOptions.snapshot] = snapshotAndOptions.options
	}

	// Write out all data.
	lastMetricsWrittenSize := int(m.lastMetricsWrittenSize.Load())
	metricsWritten := make(map[string]bool, lastMetricsWrittenSize)
	written, err := prometheus.Write(w, prometheus.ExportOptions{
		CommentHeader:  fmt.Sprintf("Data for runsc metric server exporting data for sandboxes in root directory %s", m.rootDir),
		MetricsWritten: metricsWritten,
	}, snapshotsToOptions)
	if err != nil {
		if written == 0 {
			return httpResult{http.StatusServiceUnavailable, err}
		}
		// Note that we cannot return an HTTP error here because we have already started writing a
		// response, which means we've already responded with a 200 OK status code.
		// This probably means the client closed the connection before we could finish writing.
		return httpOK
	}
	if lastMetricsWrittenSize < len(metricsWritten) {
		m.lastMetricsWrittenSize.CompareAndSwap(uint32(lastMetricsWrittenSize), uint32(len(metricsWritten)))
	}
	return httpOK
}

// serveKeepAlive extends the server's keep-alive deadline.
// Returns a response prefixed by "runsc-metrics:OK" on success.
// Clients can use this to assert that they are talking to the metrics server, as opposed to some
// other random HTTP server.
func (m *MetricServer) serveKeepAlive(w http.ResponseWriter, req *http.Request) httpResult {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.shuttingDown {
		return httpResult{http.StatusServiceUnavailable, errors.New("server is shutting down already")}
	}
	if err := req.ParseForm(); err != nil {
		return httpResult{http.StatusBadRequest, err}
	}
	rootDir := req.Form.Get("root")
	if rootDir != m.rootDir {
		return httpResult{http.StatusBadRequest, fmt.Errorf("this metric server is configured to serve root directory: %s", m.rootDir)}
	}
	m.keepAliveDeadline = time.Now().Add(keepAliveTimeout)
	w.WriteHeader(http.StatusOK)
	io.WriteString(w, fmt.Sprintf("runsc-metrics:OK: keep-alive time extended to %v", m.keepAliveDeadline))
	return httpOK
}

// serveRegisterSandbox serves requests to register sandboxes.
func (m *MetricServer) serveRegisterSandbox(w http.ResponseWriter, req *http.Request) httpResult {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.shuttingDown {
		return httpResult{http.StatusServiceUnavailable, errors.New("server is shutting down and no longer accepting new sandboxes")}
	}
	if err := req.ParseForm(); err != nil {
		return httpResult{http.StatusBadRequest, err}
	}
	rootDir := req.Form.Get("root")
	if rootDir != m.rootDir {
		return httpResult{http.StatusBadRequest, fmt.Errorf("this metric server is configured to serve root directory: %s", m.rootDir)}
	}
	sandboxID := req.Form.Get("sandbox")
	containerID := req.Form.Get("container")
	podName := req.Form.Get("pod")         // May be empty.
	namespace := req.Form.Get("namespace") // May be empty.
	if sandboxID == "" || containerID == "" {
		return httpResult{http.StatusBadRequest, errors.New("must specify non-empty sandbox ID and container ID")}
	}
	if oldSandbox, found := m.sandboxes[sandboxID]; found {
		// The sandbox may have died and this is an attempt from a restarted sandbox to re-register.
		// Check to see if it's still alive.
		if oldSandbox.sandbox.IsRunning() {
			return httpResult{http.StatusNotModified, fmt.Errorf("metrics for sandbox %s (which is still running) are already being served on this metrics server", sandboxID)}
		}
		// Otherwise, carry on, we'll just overwrite it.
	}
	// We cannot run container.Load here because metric registration happens during sandbox startup,
	// during which the container is locked. So instead we list all containers, which doesn't require
	// locking it. This allows checking for existence. The container will be loaded when a metrics
	// request comes in.
	// This also has the advantage that it doesn't directly pass the "container" parameter directly to
	// container.Load, which could potentially do some undesirable filesystem traversal stuff if it
	// wasn't properly sanitized.
	containers, err := container.List(m.rootDir)
	if err != nil {
		return httpResult{http.StatusServiceUnavailable, fmt.Errorf("cannot list containers in root directory %s: %v", m.rootDir, err)}
	}
	found := false
	var rootContainerID container.FullID
	for _, cid := range containers {
		if cid.SandboxID == sandboxID && cid.ContainerID == containerID {
			rootContainerID = cid
			found = true
			break
		}
	}
	if !found {
		return httpResult{http.StatusNotFound, fmt.Errorf("this sandbox/container pair does not exist under root %s", m.rootDir)}
	}
	m.sandboxes[sandboxID] = &servedSandbox{
		rootContainerID: rootContainerID,
		rootDir:         m.rootDir,
		extraLabels: map[string]string{
			sandbox.SandboxIDLabel: sandboxID,
			iterationIDLabel:       fmt.Sprintf("%d", m.rand.Uint64()),
		},
	}
	// Note: Pod name and namespace may be wrong initially. The correct one will be read from the
	// state file before any sandbox metric is exported. Recording it here is still useful to
	// provide identifying information when reporting sandbox presence before we can load the
	// state file. It is not a problem if this identifying information points nowhere for a while
	// until actual sandbox metrics are exported for that sandbox.
	if podName != "" {
		m.sandboxes[sandboxID].extraLabels[sandbox.PodNameLabel] = podName
	}
	if namespace != "" {
		m.sandboxes[sandboxID].extraLabels[sandbox.NamespaceLabel] = namespace
	}
	log.Infof("Registered new sandbox %v with labels %v", sandboxID, m.sandboxes[sandboxID].extraLabels)
	m.numSandboxes++
	m.extendKeepAliveLocked()
	io.WriteString(w, "sandbox registered")
	return httpOK
}

// serveUnregisterSandbox serves requests to unregister sandboxes.
func (m *MetricServer) serveUnregisterSandbox(w http.ResponseWriter, req *http.Request) httpResult {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.shuttingDown {
		return httpResult{http.StatusNotModified, errors.New("server is shutting down, so all sandboxes are already being implicitly unregistered")}
	}
	if err := req.ParseForm(); err != nil {
		return httpResult{http.StatusBadRequest, err}
	}
	rootDir := req.Form.Get("root")
	if rootDir != m.rootDir {
		return httpResult{http.StatusBadRequest, fmt.Errorf("this metric server is configured to serve root directory: %s", m.rootDir)}
	}
	sandboxID := req.Form.Get("sandbox")
	sandbox, found := m.sandboxes[sandboxID]
	if !found {
		return httpResult{http.StatusNotFound, fmt.Errorf("sandbox ID %s not found", sandboxID)}
	}
	if sandbox.sandbox != nil && sandbox.sandbox.IsRunning() {
		return httpResult{http.StatusBadRequest, errors.New("sandbox is still running")}
	}
	delete(m.sandboxes, sandboxID)
	m.extendKeepAliveLocked()
	io.WriteString(w, "sandbox unregistered")
	return httpOK
}

// serveShutdown serves requests to shut down the server.
func (m *MetricServer) serveShutdown(w http.ResponseWriter, req *http.Request) httpResult {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.persistent {
		return httpResult{http.StatusNotModified, errors.New("server is persistent")}
	}
	if m.shuttingDown {
		return httpResult{http.StatusNotModified, errors.New("server already shutting down")}
	}
	if err := req.ParseForm(); err != nil {
		return httpResult{http.StatusBadRequest, err}
	}
	rootDir := req.Form.Get("root")
	if rootDir != m.rootDir {
		return httpResult{http.StatusBadRequest, fmt.Errorf("this metric server is configured to serve root directory: %s", m.rootDir)}
	}
	log.Infof("Server shutting down from user request.")
	m.shutdownLocked(req.Context())
	io.WriteString(w, "server shutting down")
	return httpOK
}

// logRequest wraps an HTTP handler and adds logging to it.
func logRequest(f func(w http.ResponseWriter, req *http.Request) httpResult) func(w http.ResponseWriter, req *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		log.Infof("Request: %s %s", req.Method, req.URL.Path)
		defer func() {
			if r := recover(); r != nil {
				log.Warningf("Request: %s %s: Panic:\n%v", req.Method, req.URL.Path, r)
			}
		}()
		result := f(w, req)
		if result.err != nil {
			http.Error(w, result.err.Error(), result.code)
			log.Warningf("Request: %s %s: Failed with HTTP code %d: %v", req.Method, req.URL.Path, result.code, result.err)
		}
	}
}

func (m *MetricServer) verifyLoop(ctx context.Context) {
	ticker := time.NewTicker(verifyLoopInterval)
	defer ticker.Stop()
	for ctx.Err() == nil {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, err := container.List(m.rootDir); err != nil {
				m.mu.Lock()
				log.Warningf("Cannot list containers in root directory %s, it has likely gone away: %v. Server shutting down.", m.rootDir, err)
				m.shutdownLocked(ctx)
				m.mu.Unlock()
				return
			}
			func() {
				m.mu.Lock()
				defer m.mu.Unlock()
				m.purgeSandboxesLocked()
				if m.persistent {
					// Server is persistent, so no need to check if no more sandboxes are running.
					return
				}
				if len(m.sandboxes) > 0 {
					// There are still sandboxes running, so we're happy.
					return
				}
				// There are no sandboxes running; see if it's time that we need to shut down.
				now := time.Now()
				if !m.keepAliveDeadline.IsZero() && now.Before(m.keepAliveDeadline) {
					log.Warningf("Serving metrics for no sandboxes, but server will stay alive until %v before shutting down.", m.keepAliveDeadline)
					return
				}
				if m.numSandboxes == 0 && now.Before(m.firstSandboxDeadline) {
					log.Warningf("No sandboxes have registered for metrics since we started. Will wait until %v before shutting down.", m.firstSandboxDeadline)
					return
				}
				if m.numSandboxes > 0 {
					// We've seen at least one sandbox be registered since server startup.
					log.Infof("No more sandboxes are being served. Shutting down normally.")
				} else {
					// Since the server is usually only spawned in the context of providing instrumentation
					// for a sandbox, it is generally an error if we've never seen any sandbox register since
					// server startup.
					log.Warningf("No sandboxes have registered for metrics since we started, and deadline %v is exceeded. Shutting down.", m.firstSandboxDeadline)
				}
				m.shutdownLocked(ctx)
			}()
		}
	}
}

// Execute implements subcommands.Command.Execute.
func (m *MetricServer) Execute(ctx context.Context, f *flag.FlagSet, args ...any) subcommands.ExitStatus {
	ctx, ctxCancel := context.WithCancel(ctx)
	defer ctxCancel()

	if f.NArg() != 0 {
		f.Usage()
		return subcommands.ExitUsageError
	}
	conf := args[0].(*config.Config)
	if _, err := container.List(conf.RootDir); err != nil {
		return util.Errorf("Invalid root directory %q: tried to list containers within it and got: %v", conf.RootDir, err)
	}
	if conf.MetricServer == "" || conf.RootDir == "" {
		f.Usage()
		return subcommands.ExitUsageError
	}
	if strings.Contains(conf.MetricServer, "%ID%") {
		return util.Errorf("Metric server address contains '%%ID%%': %v. This should have been replaced by the parent process.", conf.MetricServer)
	}
	m.startTime = time.Now()
	m.rand = rand.New(rand.NewSource(m.startTime.UnixNano()))
	m.persistent = conf.MetricServerPersist
	m.rootDir = conf.RootDir
	m.exporterPrefix = conf.MetricExporterPrefix
	if strings.Contains(conf.MetricServer, "%RUNTIME_ROOT%") {
		newAddr := strings.ReplaceAll(conf.MetricServer, "%RUNTIME_ROOT%", m.rootDir)
		log.Infof("Metric server address replaced %RUNTIME_ROOT%: %q -> %q", conf.MetricServer, newAddr)
		conf.MetricServer = newAddr
	}
	m.sandboxes = make(map[string]*servedSandbox)

	var listener net.Listener
	var listenErr error
	if strings.HasPrefix(conf.MetricServer, fmt.Sprintf("%c", os.PathSeparator)) {
		beforeBindSt, beforeBindErr := os.Stat(conf.MetricServer)
		if listener, listenErr = (&net.ListenConfig{}).Listen(ctx, "unix", conf.MetricServer); listenErr != nil {
			return util.Errorf("Cannot listen on unix domain socket %q: %v", conf.MetricServer, listenErr)
		}
		afterBindSt, afterBindErr := os.Stat(conf.MetricServer)
		if afterBindErr != nil {
			return util.Errorf("Cannot stat our own unix domain socket %q: %v", conf.MetricServer, afterBindErr)
		}
		ownUDS := true
		if beforeBindErr == nil && beforeBindSt.Mode() == afterBindSt.Mode() {
			// Socket file existed and was a socket prior to us binding to it.
			if beforeBindSt.Sys() != nil && afterBindSt.Sys() != nil {
				beforeSt, beforeStOk := beforeBindSt.Sys().(*syscall.Stat_t)
				afterSt, afterStOk := beforeBindSt.Sys().(*syscall.Stat_t)
				if beforeStOk && afterStOk && beforeSt.Dev == afterSt.Dev && beforeSt.Ino == afterSt.Ino {
					// Socket file is the same before and after binding, so we should not consider ourselves
					// the owner of it.
					ownUDS = false
				}
			}
		}
		if ownUDS {
			log.Infof("Bound on socket file %s which we own. As such, this socket file will be deleted on server shutdown.", conf.MetricServer)
			m.udsPath = conf.MetricServer

			// Note: This socket file may also be removed earlier during clean server shutdown.
			// We still need this here to handle cases where proper shutdown isn't called or if we
			// encounter errors before the server is fully initialized.
			defer os.Remove(m.udsPath)

			os.Chmod(m.udsPath, 0777)
		} else {
			log.Infof("Bound on socket file %s which existed prior to this server's existence. As such, it will not be deleted on server shutdown.", conf.MetricServer)
		}
	} else {
		if strings.HasPrefix(conf.MetricServer, ":") {
			log.Warningf("Binding on all interfaces. This will allow anyone to list all containers on your machine!")
		}
		if listener, listenErr = (&net.ListenConfig{}).Listen(ctx, "tcp", conf.MetricServer); listenErr != nil {
			return util.Errorf("Cannot listen on TCP address %q: %v", conf.MetricServer, listenErr)
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", logRequest(m.serveMetrics))
	mux.HandleFunc("/runsc-metrics/keep-alive", logRequest(m.serveKeepAlive))
	mux.HandleFunc("/runsc-metrics/register-sandbox", logRequest(m.serveRegisterSandbox))
	mux.HandleFunc("/runsc-metrics/unregister-sandbox", logRequest(m.serveUnregisterSandbox))
	mux.HandleFunc("/runsc-metrics/shutdown", logRequest(m.serveShutdown))
	mux.HandleFunc("/", logRequest(m.serveIndex))
	m.srv.Handler = mux
	m.srv.ReadTimeout = httpTimeout
	m.srv.WriteTimeout = httpTimeout
	m.firstSandboxDeadline = time.Now().Add(firstSandboxTimeout)
	log.Infof("Server serving on %s for root directory %s. Will stay up until at least %v.", conf.MetricServer, conf.RootDir, m.firstSandboxDeadline)

	go m.verifyLoop(ctx)
	serveErr := m.srv.Serve(listener)
	log.Infof("Server has stopped accepting requests.")
	m.mu.Lock()
	defer m.mu.Unlock()
	if serveErr != nil {
		if serveErr == http.ErrServerClosed {
			if m.numSandboxes > 0 {
				return subcommands.ExitSuccess
			}
			return util.Errorf("Metrics server never served metrics for any sandbox")
		}
		return util.Errorf("Cannot serve on address %s: %v", conf.MetricServer, serveErr)
	}
	// Per documentation, http.Server.Serve can never return a nil error, so this is not a success.
	return util.Errorf("HTTP server Serve() did not return expected error")
}
