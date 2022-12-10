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

package sandbox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/cenkalti/backoff"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/specutils"
)

// MetricClient implements an HTTP client that can spawn and connect to a running runsc metrics
// server process and register/unregister sandbox metrics.
type MetricClient struct {
	addr    string
	rootDir string
	dialer  net.Dialer
	client  http.Client
}

// NewMetricClient creates a new MetricClient that can talk to the metric server at address addr.
func NewMetricClient(addr, rootDir string) *MetricClient {
	c := &MetricClient{
		addr:    strings.ReplaceAll(addr, "%RUNTIME_ROOT%", rootDir),
		rootDir: rootDir,
		dialer: net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		},
		client: http.Client{
			Transport: &http.Transport{
				// We only talk over the local network, so no need to spend CPU on compression.
				DisableCompression:    true,
				MaxIdleConns:          1,
				IdleConnTimeout:       30 * time.Second,
				ResponseHeaderTimeout: 30 * time.Second,
				ExpectContinueTimeout: 30 * time.Second,
			},
			Timeout: 30 * time.Second,
		},
	}
	// In order to support talking HTTP over Unix domain sockets, we use a custom dialer
	// which knows how to dial the right address.
	// The HTTP address passed as URL to the client is ignored.
	c.client.Transport.(*http.Transport).DialContext = c.dialContext
	return c
}

// dialContext dials the metric server. It ignores whatever address is given to it.
func (c *MetricClient) dialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	var network string
	if strings.HasPrefix(c.addr, fmt.Sprintf("%c", os.PathSeparator)) {
		network = "unix"
	} else {
		network = "tcp"
	}
	return c.dialer.DialContext(ctx, network, c.addr)
}

// Close closes any idle HTTP connection.
func (c *MetricClient) Close() {
	c.client.CloseIdleConnections()
}

// req performs an HTTP request against the metrics server.
// It returns an http.Response, and a function to close out the request that should be called when
// the response is no longer necessary.
func (c *MetricClient) req(ctx context.Context, timeout time.Duration, endpoint string, params map[string]string) (*http.Response, func(), error) {
	cancelFunc := context.CancelFunc(func() {})
	if timeout != 0 {
		ctx, cancelFunc = context.WithTimeout(ctx, timeout)
	}
	var method string
	var bodyBytes io.Reader
	if params == nil {
		method = http.MethodGet
	} else {
		method = http.MethodPost
		values := url.Values{}
		for k, v := range params {
			values.Set(k, v)
		}
		bodyBytes = strings.NewReader(values.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, method, fmt.Sprintf("http://runsc-metrics%s", endpoint), bodyBytes)
	if err != nil {
		cancelFunc()
		return nil, nil, fmt.Errorf("cannot create request object: %v", err)
	}
	if params != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := c.client.Do(req)
	if err != nil {
		cancelFunc()
		return nil, nil, err
	}
	return resp, func() {
		resp.Body.Close()
		cancelFunc()
	}, err
}

// keepAlive pokes the metrics server to keep it alive for a while longer.
// If this method succeeds, the metrics server is running and is guaranteed to stay up for the next
// few minutes.
func (c *MetricClient) keepAlive(ctx context.Context) error {
	// There are multiple scenarios here:
	//  - The server isn't running. We'll get a "connection failed" error.
	//  - There is an HTTP server bound to the address, but it is not the metric server.
	//    We'll fail the /runsc-metrics/keep-alive request with an HTTP error code if that's the case.
	//  - There is a server bound to the address, but it is not the metric server and doesn't speak
	//    HTTP. We'll fail the request if that's the case.
	//  - The server is running, and the /runsc-metrics/keep-alive request succeeds.
	//  - The server is running, but it is shutting down. The metrics server will fail the
	//    /runsc-metrics/keep-alive request in this case.
	//  - The server was started by another process, but hasn't yet bound to its address by the time
	//    we send the /runsc-metrics/keep-alive request. We'll fail with a "connection failed" error.
	// To handle all of these cases, we must retry a few times on "connection failed" errors.
	resp, closeReq, err := c.req(ctx, 5*time.Second, "/runsc-metrics/keep-alive", map[string]string{
		"root": c.rootDir,
	})
	if err != nil {
		return err
	}
	defer closeReq()
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(resp.Body); err != nil {
		return err
	}
	if !strings.HasPrefix(buf.String(), "runsc-metrics:OK") {
		return errors.New("server responded to request but not with the expected prefix")
	}
	return nil
}

// spawnServer forks and executes `runsc metric-server`.
func (c *MetricClient) spawnServer(conf *config.Config) (*exec.Cmd, error) {
	// Overriden metric server address with the address this metric client is configured to use.
	// This should be the same but may contain string replacements (e.g. "%ID%").
	overriddenConf := *conf
	overriddenConf.MetricServer = c.addr
	overriddenConf.RootDir = c.rootDir
	cmd := exec.Command(specutils.ExePath, overriddenConf.ToFlags()...)
	cmd.SysProcAttr = &unix.SysProcAttr{
		// Detach from this session, otherwise cmd will get SIGHUP and SIGCONT
		// when re-parented.
		Setsid: true,
	}
	devnull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0755)
	if err != nil {
		return nil, fmt.Errorf("cannot open devnull at %s: %w", os.DevNull, err)
	}
	defer devnull.Close() // Don't leak file descriptors.
	cmd.Stdin = devnull
	cmd.Stdout = devnull
	cmd.Stderr = devnull
	// Set Args[0] to make easier to spot the sandbox process. Otherwise it's
	// shown as `exe`.
	cmd.Args[0] = "runsc-metrics"
	cmd.Args = append(cmd.Args, "metric-server")
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("cannot start metrics server: %w", err)
	}
	return cmd, nil
}

// KickOff checks whether a metric srever is running at the expected address.
// If yes, it keeps it alive for a while.
// If not, it starts one, waits for it to start, and then kicks it alive for a while too.
func (c *MetricClient) KickOff(ctx context.Context, conf *config.Config) error {
	if c.keepAlive(ctx) == nil {
		// Server is already running and we just kept it alive for a while longer. We're happy.
		return nil
	}
	// Fork off a new server.
	// Note that this code may race with another runsc instance trying to start the metrics server
	// too. How this manifests is that both server processes will race to bind to the given address.
	// Whichever server loses the race will exit with an error code, and whichever one wins will stay
	// alive.
	// As a result, we cannot use the process's return code here to determine success of the metrics
	// server to start. All we can do is to try to connect where we expect it to bind, and if our
	// process loses the race, that's OK, we'll just be talking to the race winner.
	// Another possible race condition is that there is another server in the process of shutting down
	// which has not yet unbound itself from the port or UDS that we're trying to bind ourselves to.
	// This will manifest as the /runsc-metrics/keep-alive request failing, but any attempt to bind to
	// the port/UDS will still fail, and our metrics server will crash. If this happens, and the
	// existing metrics server eventually exits, we'll find ourselves with no metrics server running
	// at all. Therefore, to avoid this, we must respawn a metrics server process every time we can
	// see that our own has died, until it eventually either comes up, or another metrics server
	// successfully comes up.
	// We use exponential backoff to avoid consuming lots of system resources in case something is
	// wrong with the metrics server, e.g. the port is used by another type of server that won't ever
	// release its port.
	bindCtx, bindCancel := context.WithTimeout(ctx, 5*time.Second)
	defer bindCancel()
	launchBackoff := backoff.WithContext(&backoff.ExponentialBackOff{
		InitialInterval:     time.Millisecond,
		Multiplier:          2,
		MaxInterval:         250 * time.Millisecond,
		RandomizationFactor: 0.1,
		Clock:               backoff.SystemClock,
	}, bindCtx)
	cmd, err := c.spawnServer(conf)
	if err != nil {
		return err
	}
	launchBackoff.Reset()
	for bindCtx.Err() == nil && c.keepAlive(bindCtx) != nil {
		if unix.Kill(cmd.Process.Pid, 0) != nil {
			// Subprocess has died, so we need to start a new one.
			cmd.Process.Kill() // This will fail, but we don't care.
			cmd.Wait()         // Reap child. This will fail, but we don't care.
			if cmd, err = c.spawnServer(conf); err != nil {
				return err
			}
		}
		nextBackoff := launchBackoff.NextBackOff()
		if nextBackoff == backoff.Stop {
			break
		}
		time.Sleep(nextBackoff)
	}
	if bindCtx.Err() != nil {
		return fmt.Errorf("metrics server did not bind to %s in time: %w", c.addr, bindCtx.Err())
	}
	return nil
}

// RegisterSandbox registers a sandbox (and its set of registered metrics) with the metrics server.
func (c *MetricClient) RegisterSandbox(ctx context.Context, sandbox *Sandbox, containerID string) error {
	_, closeReq, err := c.req(ctx, 5*time.Second, "/runsc-metrics/register-sandbox", map[string]string{
		"root":      c.rootDir,
		"sandbox":   sandbox.ID,
		"container": containerID,
	})
	if err != nil {
		return err
	}
	closeReq()
	return nil
}

// UnregisterSandbox asks the metrics server to forget about the given sandbox ID.
// Note that the metrics server will also automatically forget about sandboxes that it observes to
// no longer be running after a while.
func (c *MetricClient) UnregisterSandbox(ctx context.Context, sandboxID string) error {
	_, closeReq, err := c.req(ctx, 5*time.Second, "/runsc-metrics/unregister-sandbox", map[string]string{
		"root":    c.rootDir,
		"sandbox": sandboxID,
	})
	if err != nil {
		return err
	}
	closeReq()
	return nil
}

// ShutdownServer asks the metrics server to shut itself down.
// Useful in tests for faster cleanup.
func (c *MetricClient) ShutdownServer(ctx context.Context) error {
	_, closeReq, err := c.req(ctx, 5*time.Second, "/runsc-metrics/shutdown", map[string]string{
		"root": c.rootDir,
	})
	if err != nil {
		return err
	}
	closeReq()
	c.Close()
	return nil
}

// GetMetrics returns the raw, Prometheus-formatted metric data from the metric server.
func (c *MetricClient) GetMetrics(ctx context.Context) (string, error) {
	resp, closeReq, err := c.req(ctx, 10*time.Second, "/metrics", nil)
	if err != nil {
		return "", fmt.Errorf("cannot get /metrics: %v", err)
	}
	defer closeReq()
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(resp.Body); err != nil {
		return "", fmt.Errorf("cannot read from response body: %v", err)
	}
	return buf.String(), nil
}
