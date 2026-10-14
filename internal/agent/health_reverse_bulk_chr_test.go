package agent

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testLiveReverseBulk(t *testing.T, parent context.Context, runtime *xraySelectorRuntime, selected, target string, corePID int) {
	t.Helper()
	endpoint, err := url.Parse(target)
	if err != nil {
		t.Fatal(err)
	}
	const payload = 8 * 1024 * 1024
	for _, path := range []string{"/bulk", "/bulk/paced"} {
		for _, streams := range []int{1, 4} {
			t.Run(fmt.Sprintf("bulk%s/streams-%d", path, streams), func(t *testing.T) {
				endpoint.Path = path
				ctx, cancel := context.WithTimeout(parent, 8*time.Second)
				defer cancel()
				var workers sync.WaitGroup
				var bytes, completed, failed atomic.Int64
				at := time.Now()
				cpuBefore := testReverseProcessCPUTicks(t, os.Getpid(), corePID)
				for range streams {
					workers.Go(func() {
						for ctx.Err() == nil {
							n, err := downloadThroughProxyContext(ctx, runtime.opts.ProbeURL, endpoint.String(), 15*time.Second, payload, http.StatusOK)
							bytes.Add(int64(n))
							if ctx.Err() != nil {
								return
							}
							if err != nil || n != payload {
								failed.Add(1)
								t.Logf("bulk transfer failed before phase cancellation: bytes=%d elapsed=%s error=%v", n, time.Since(at), err)
								return
							} else {
								completed.Add(1)
							}
						}
					})
				}
				var good, bad int
				for ctx.Err() == nil {
					if evidence := runtime.ProbeAvailability(selected); evidence.OK {
						good++
					} else {
						bad++
						t.Logf("bulk availability failed: elapsed=%s evidence=%+v", time.Since(at), evidence)
					}
					if !wait(ctx, time.Second) {
						break
					}
				}
				cancel()
				workers.Wait()
				elapsed := time.Since(at)
				cpuTicks := testReverseProcessCPUTicks(t, os.Getpid(), corePID) - cpuBefore
				cpuPerMiB := float64(cpuTicks) / (float64(bytes.Load()) / (1024 * 1024))
				t.Logf("bulk streams=%d path=%s mbps=%.2f completed=%d failures=%d probes_ok=%d probes_failed=%d cpu_ticks=%d cpu_ticks_per_mib=%.2f elapsed=%s scope=local_HTTPS_download_test_and_core", streams, path, float64(bytes.Load())*8/elapsed.Seconds()/1e6, completed.Load(), failed.Load(), good, bad, cpuTicks, cpuPerMiB, elapsed)
				if bytes.Load() == 0 || failed.Load() != 0 || bad != 0 {
					t.Fatal("local bulk transfer or concurrent availability failed")
				}
			})
		}
	}
}
