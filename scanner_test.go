package portscan

import (
	"context"
	"errors"
	"io"
	"net"
	"runtime"
	"slices"
	"sync"
	"syscall"
	"testing"
	"time"
)

func newTestScanner(t *testing.T, concurrency int) *Scanner {
	t.Helper()
	scanner, err := New(concurrency, time.Second)
	if err != nil {
		t.Fatalf("New(%d, %s): %v", concurrency, time.Second, err)
	}
	return scanner
}

func newTestListener(t *testing.T, network, address string) net.Listener {
	t.Helper()
	listener, err := net.Listen(network, address)
	if err != nil {
		t.Fatalf("net.Listen(%q, %q): %v", network, address, err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return listener
}

func TestNew(t *testing.T) {
	tests := []struct {
		name        string
		concurrency int
		timeout     time.Duration
		wantErr     bool
	}{
		{
			name:        "valid",
			concurrency: 10,
			timeout:     time.Second,
		},
		{
			name:        "zero concurrency",
			concurrency: 0,
			timeout:     time.Second,
			wantErr:     true,
		},
		{
			name:        "negative concurrency",
			concurrency: -1,
			timeout:     time.Second,
			wantErr:     true,
		},
		{
			name:        "zero timeout",
			concurrency: 10,
			timeout:     0,
			wantErr:     true,
		},
		{
			name:        "negative timeout",
			concurrency: 10,
			timeout:     -time.Second,
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner, err := New(tt.concurrency, tt.timeout)
			if tt.wantErr {
				if err == nil || scanner != nil {
					t.Fatalf("expected error and nil scanner, got scanner=%v err=%v", scanner, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected New error: %v", err)
			}
			if scanner == nil {
				t.Fatal("expected non-nil scanner")
			}
			if scanner.maxConcurrency != tt.concurrency || scanner.timeout != tt.timeout {
				t.Fatalf("unexpected scanner settings: concurrency=%d, timeout=%s", scanner.maxConcurrency, scanner.timeout)
			}
		})
	}
}

func TestValidatePortOpen(t *testing.T) {
	scanner := newTestScanner(t, 10)
	listener := newTestListener(t, "tcp4", "127.0.0.1:0")
	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	ip := net.ParseIP("127.0.0.1")

	result := scanner.validatePort(context.Background(), "127.0.0.1", port, ip)
	if result.State != StateOpen || result.Err != nil || result.Port != port || !result.IP.Equal(ip) {
		t.Fatalf("unexpected open-port result: %+v", result)
	}
}

func TestValidatePortClosed(t *testing.T) {
	scanner := newTestScanner(t, 10)
	listener := newTestListener(t, "tcp4", "127.0.0.1:0")
	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	if err := listener.Close(); err != nil {
		t.Fatalf("failed to close listener: %v", err)
	}

	result := scanner.validatePort(context.Background(), "127.0.0.1", port, net.ParseIP("127.0.0.1"))
	if result.State != StateClosed || result.Err == nil || result.Host != "127.0.0.1" || result.Port != port {
		t.Fatalf("unexpected closed-port result: %+v", result)
	}
}

func TestValidatePortCanceled(t *testing.T) {
	scanner := newTestScanner(t, 10)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result := scanner.validatePort(ctx, "127.0.0.1", 8080, net.ParseIP("127.0.0.1"))
	if result.State != StateCanceled || !errors.Is(result.Err, context.Canceled) {
		t.Fatalf("expected canceled result, got %+v", result)
	}
}

func TestValidatePortTimeout(t *testing.T) {
	scanner := newTestScanner(t, 10)
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()

	result := scanner.validatePort(ctx, "127.0.0.1", 8080, net.ParseIP("127.0.0.1"))
	if result.State != StateTimeout || !errors.Is(result.Err, context.DeadlineExceeded) {
		t.Fatalf("expected timed-out result, got %+v", result)
	}
}

func TestClassifyError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want State
	}{
		{
			name: "canceled",
			err:  context.Canceled,
			want: StateCanceled,
		},
		{
			name: "deadline",
			err:  context.DeadlineExceeded,
			want: StateTimeout,
		},
		{
			name: "timeout",
			err:  &net.DNSError{IsTimeout: true},
			want: StateTimeout,
		},
		{
			name: "refused",
			err:  syscall.ECONNREFUSED,
			want: StateClosed,
		},
		{
			name: "host unreachable",
			err:  syscall.EHOSTUNREACH,
			want: StateUnreachable,
		},
		{
			name: "network unreachable",
			err:  syscall.ENETUNREACH,
			want: StateUnreachable,
		},
		{
			name: "other",
			err:  errors.New("unknown error"),
			want: StateError,
		},
	}
	if runtime.GOOS == "windows" {
		tests = append(tests, struct {
			name string
			err  error
			want State
		}{
			name: "windows refused",
			err:  syscall.Errno(10061),
			want: StateClosed,
		})
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifyError(tt.err); got != tt.want {
				t.Fatalf("classifyError(%v): expected %s, got %s", tt.err, tt.want, got)
			}
		})
	}
}

func TestResolverHost(t *testing.T) {
	addresses, err := resolveHost(context.Background(), "127.0.0.1")
	if err != nil {
		t.Fatalf("resolve IPv4 literal: %v", err)
	}
	if len(addresses) != 1 || !addresses[0].IP.Equal(net.ParseIP("127.0.0.1")) {
		t.Fatalf("unexpected IPv4 resolution: %v", addresses)
	}
}

func TestResolverHostIPv6(t *testing.T) {
	addresses, err := resolveHost(context.Background(), "::1")
	if err != nil {
		t.Fatalf("resolve IPv6 literal: %v", err)
	}
	if len(addresses) != 1 || !addresses[0].IP.Equal(net.ParseIP("::1")) {
		t.Fatalf("unexpected IPv6 resolution: %v", addresses)
	}
}

func TestResolverHostName(t *testing.T) {
	addresses, err := resolveHost(context.Background(), "localhost")
	if err != nil {
		t.Fatalf("resolve localhost: %v", err)
	}
	if len(addresses) == 0 {
		t.Fatal("expected at least one IP address for localhost")
	}
	for _, addr := range addresses {
		if addr.IP == nil {
			t.Fatalf("localhost resolved to nil IP: %v", addresses)
		}
	}
}

func TestResolverHostInvalidName(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	addresses, err := resolveHost(ctx, "bad..host")
	if err == nil || addresses != nil {
		t.Fatalf("expected resolution error and nil addresses, got addresses=%v err=%v", addresses, err)
	}
	if ctx.Err() != nil {
		t.Fatalf("invalid-name resolution exceeded deadline: %v", ctx.Err())
	}
}

func TestScanOpenPort(t *testing.T) {
	scanner := newTestScanner(t, 10)
	listener := newTestListener(t, "tcp4", "127.0.0.1:0")
	port := uint16(listener.Addr().(*net.TCPAddr).Port)

	results, err := scanner.Scan(context.Background(), []string{"127.0.0.1"}, []uint16{port})
	if err != nil {
		t.Fatalf("failed to start scan: %v", err)
	}
	count := 0
	for result := range results {
		count++
		if result.State != StateOpen || result.Port != port || result.Err != nil {
			t.Fatalf("unexpected open-port result: %+v", result)
		}
	}
	if count != 1 {
		t.Fatalf("expected 1 result, got %d", count)
	}
}

func TestScanClosedPort(t *testing.T) {
	scanner := newTestScanner(t, 10)
	listener := newTestListener(t, "tcp4", "127.0.0.1:0")
	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	if err := listener.Close(); err != nil {
		t.Fatalf("failed to close listener: %v", err)
	}

	results, err := scanner.Scan(context.Background(), []string{"127.0.0.1"}, []uint16{port})
	if err != nil {
		t.Fatalf("failed to start scan: %v", err)
	}
	count := 0
	for result := range results {
		count++
		if result.State != StateClosed || result.Port != port || result.Err == nil {
			t.Fatalf("unexpected closed-port result: %+v", result)
		}
	}
	if count != 1 {
		t.Fatalf("expected 1 result, got %d", count)
	}
}

func TestScanMultiplePorts(t *testing.T) {
	scanner := newTestScanner(t, 3)
	first := newTestListener(t, "tcp4", "127.0.0.1:0")
	second := newTestListener(t, "tcp4", "127.0.0.1:0")
	firstPort := uint16(first.Addr().(*net.TCPAddr).Port)
	secondPort := uint16(second.Addr().(*net.TCPAddr).Port)

	results, err := scanner.Scan(context.Background(), []string{"127.0.0.1"}, []uint16{firstPort, secondPort})
	if err != nil {
		t.Fatalf("failed to start scan: %v", err)
	}
	seen := make(map[uint16]int)
	for result := range results {
		if result.State != StateOpen {
			t.Fatalf("port %d: expected open, got %s: %v", result.Port, result.State, result.Err)
		}
		seen[result.Port]++
	}
	if len(seen) != 2 || seen[firstPort] != 1 || seen[secondPort] != 1 {
		t.Fatalf("expected exactly one result for ports %d and %d, got %v", firstPort, secondPort, seen)
	}
}

func TestScanManyPorts(t *testing.T) {
	scanner := newTestScanner(t, 10)
	ports, err := Range(10000, 10999)
	if err != nil {
		t.Fatalf("failed to create port range: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	results, err := scanner.Scan(ctx, []string{"127.0.0.1"}, ports)
	if err != nil {
		t.Fatalf("failed to start scan: %v", err)
	}
	count := 0
	for range results {
		count++
	}
	if count != len(ports) {
		t.Fatalf("expected %d results, got %d (ctx: %v)", len(ports), count, ctx.Err())
	}
}

func TestScanCancellationClosesResults(t *testing.T) {
	scanner := newTestScanner(t, 10)
	ports, err := Range(10000, 10999)
	if err != nil {
		t.Fatalf("failed to create port range: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	results, err := scanner.Scan(ctx, []string{"127.0.0.1"}, ports)
	if err != nil {
		t.Fatalf("failed to start scan: %v", err)
	}
	cancel()

	timeout := time.After(2 * time.Second)
	for {
		select {
		case _, ok := <-results:
			if !ok {
				return
			}
		case <-timeout:
			t.Fatal("results channel did not close after cancellation")
		}
	}
}

func TestScanCancelWithUnreadResults(t *testing.T) {
	scanner := newTestScanner(t, 1)
	listener := newTestListener(t, "tcp4", "127.0.0.1:0")
	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	results, err := scanner.Scan(ctx, []string{"127.0.0.1"}, []uint16{port})
	if err != nil {
		t.Fatalf("failed to start scan: %v", err)
	}
	if err := listener.(*net.TCPListener).SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("failed to set accept deadline: %v", err)
	}
	conn, err := listener.Accept()
	if err != nil {
		t.Fatalf("failed to accept connection: %v", err)
	}
	_ = conn.Close()

	cancel()
	timeout := time.After(2 * time.Second)
	for {
		select {
		case _, ok := <-results:
			if !ok {
				return
			}
		case <-timeout:
			t.Fatal("results channel did not close after cancellation with unread results")
		}
	}
}

func TestScanConcurrencyLimit(t *testing.T) {
	scanner := newTestScanner(t, 3)
	ports, err := Range(10000, 10009)
	if err != nil {
		t.Fatalf("failed to create port range: %v", err)
	}

	var mu sync.Mutex
	active, maxActive := 0, 0
	release := make(chan struct{})
	started := make(chan struct{}, len(ports))

	scanner.dialFn = func(ctx context.Context, network, address string) (net.Conn, error) {
		mu.Lock()
		active++
		if active > maxActive {
			maxActive = active
		}
		mu.Unlock()

		started <- struct{}{}
		defer func() {
			mu.Lock()
			active--
			mu.Unlock()
		}()

		select {
		case <-release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return nil, syscall.ECONNREFUSED
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	results, err := scanner.Scan(ctx, []string{"127.0.0.1"}, ports)
	if err != nil {
		t.Fatalf("failed to start scan: %v", err)
	}
	for i := 0; i < scanner.maxConcurrency; i++ {
		select {
		case <-started:
		case <-ctx.Done():
			t.Fatalf("expected %d concurrent dial attempts, started only %d", scanner.maxConcurrency, i)
		}
	}

	mu.Lock()
	observed := maxActive
	mu.Unlock()
	if observed != scanner.maxConcurrency {
		t.Fatalf("expected %d concurrent dial attempts, observed %d", scanner.maxConcurrency, observed)
	}

	close(release)
	count := 0
	for range results {
		count++
	}
	if count != len(ports) {
		t.Fatalf("expected %d results, got %d", len(ports), count)
	}
	if maxActive > scanner.maxConcurrency {
		t.Fatalf("concurrency limit exceeded: at most %d, observed %d", scanner.maxConcurrency, maxActive)
	}
}

func TestScanDuplicateInputs(t *testing.T) {
	scanner := newTestScanner(t, 3)
	listener := newTestListener(t, "tcp4", "127.0.0.1:0")
	port := uint16(listener.Addr().(*net.TCPAddr).Port)

	hosts := []string{"127.0.0.1", "127.0.0.1", "127.0.0.1"}
	ports := []uint16{port, port, port}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	results, err := scanner.Scan(ctx, hosts, ports)
	if err != nil {
		t.Fatalf("failed to start scan: %v", err)
	}

	count := 0
	for result := range results {
		count++
		if result.State != StateOpen || result.Port != port {
			t.Fatalf("unexpected deduplicated result: %+v", result)
		}
	}
	if count != 1 {
		t.Fatalf("expected exactly 1 result after deduplication, got %d", count)
	}
}

func TestScanInvalidInputs(t *testing.T) {
	scanner := newTestScanner(t, 3)
	tests := []struct {
		name  string
		ctx   context.Context
		hosts []string
		ports []uint16
	}{
		{
			name:  "empty hosts",
			ctx:   context.Background(),
			hosts: []string{},
			ports: []uint16{80},
		},
		{
			name:  "empty ports",
			ctx:   context.Background(),
			hosts: []string{"127.0.0.1"},
			ports: []uint16{},
		},
		{
			name:  "nil context",
			ctx:   nil,
			hosts: []string{"127.0.0.1"},
			ports: []uint16{80},
		},
		{
			name:  "invalid port zero",
			ctx:   context.Background(),
			hosts: []string{"127.0.0.1"},
			ports: []uint16{0},
		},
		{
			name:  "empty host string",
			ctx:   context.Background(),
			hosts: []string{"  "},
			ports: []uint16{80},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results, err := scanner.Scan(tt.ctx, tt.hosts, tt.ports)
			if err == nil || results != nil {
				t.Fatalf("expected error and nil results channel, got results=%v err=%v", results, err)
			}
		})
	}
}

func TestRangeInvalidInputs(t *testing.T) {
	tests := []struct {
		name     string
		start    int
		end      int
		wantErr  bool
		wantPort uint16
	}{
		{
			name:    "zero start",
			start:   0,
			end:     10,
			wantErr: true,
		},
		{
			name:    "negative start",
			start:   -1,
			end:     10,
			wantErr: true,
		},
		{
			name:    "reversed range",
			start:   100,
			end:     99,
			wantErr: true,
		},
		{
			name:    "port above maximum",
			start:   65536,
			end:     65536,
			wantErr: true,
		},
		{
			name:     "single valid port",
			start:    80,
			end:      80,
			wantPort: 80,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ports, err := Range(tt.start, tt.end)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for Range(%d, %d)", tt.start, tt.end)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected Range error: %v", err)
			}
			if len(ports) != 1 || ports[0] != tt.wantPort {
				t.Fatalf("expected [%d], got %v", tt.wantPort, ports)
			}
		})
	}
}

func TestMergePorts(t *testing.T) {
	tests := []struct {
		name    string
		groups  [][]uint16
		want    []uint16
		wantErr bool
	}{
		{
			name:   "merge different ports",
			groups: [][]uint16{{80, 443}, {22, 8080}},
			want:   []uint16{22, 80, 443, 8080},
		},
		{
			name:   "remove duplicates",
			groups: [][]uint16{{80, 443, 80}, {443, 22, 22}},
			want:   []uint16{22, 80, 443},
		},
		{
			name:   "single group",
			groups: [][]uint16{{80, 443}},
			want:   []uint16{80, 443},
		},
		{
			name:    "empty groups",
			groups:  [][]uint16{},
			wantErr: true,
		},
		{
			name:   "mixed empty groups",
			groups: [][]uint16{{}, {80, 443}, {}},
			want:   []uint16{80, 443},
		},
		{
			name:    "zero port",
			groups:  [][]uint16{{80, 0}},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := MergePorts(tt.groups...)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected MergePorts error: %v", err)
			}
			slices.Sort(got)
			want := slices.Clone(tt.want)
			slices.Sort(want)
			if !slices.Equal(got, want) {
				t.Fatalf("expected ports %v, got %v", want, got)
			}
		})
	}
}

func TestMergeHosts(t *testing.T) {
	tests := []struct {
		name    string
		groups  [][]string
		want    []string
		wantErr bool
	}{
		{
			name:   "merge different hosts",
			groups: [][]string{{"127.0.0.1", "localhost"}, {"192.168.1.1"}},
			want:   []string{"127.0.0.1", "localhost", "192.168.1.1"},
		},
		{
			name:   "remove duplicates",
			groups: [][]string{{"127.0.0.1", "localhost"}, {"localhost", "127.0.0.1"}},
			want:   []string{"127.0.0.1", "localhost"},
		},
		{
			name:   "trim spaces",
			groups: [][]string{{" 127.0.0.1 ", " localhost "}, {"127.0.0.1"}},
			want:   []string{"127.0.0.1", "localhost"},
		},
		{
			name:    "empty groups",
			groups:  [][]string{},
			wantErr: true,
		},
		{
			name:    "empty host",
			groups:  [][]string{{"127.0.0.1", ""}},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := MergeHosts(tt.groups...)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected MergeHosts error: %v", err)
			}
			slices.Sort(got)
			want := slices.Clone(tt.want)
			slices.Sort(want)
			if !slices.Equal(got, want) {
				t.Fatalf("expected hosts %v, got %v", want, got)
			}
		})
	}
}

func TestScanReuse(t *testing.T) {
	scanner := newTestScanner(t, 3)
	listener := newTestListener(t, "tcp4", "127.0.0.1:0")
	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	for attempt := 1; attempt <= 2; attempt++ {
		results, err := scanner.Scan(ctx, []string{"127.0.0.1"}, []uint16{port})
		if err != nil {
			t.Fatalf("scan %d: failed to start: %v", attempt, err)
		}
		count := 0
		for result := range results {
			count++
			if result.State != StateOpen || result.Port != port {
				t.Fatalf("scan %d: unexpected result: %+v", attempt, result)
			}
		}
		if count != 1 {
			t.Fatalf("scan %d: expected 1 result, got %d", attempt, count)
		}
	}
}

func TestScanConcurrentReuse(t *testing.T) {
	scanner := newTestScanner(t, 3)
	listener := newTestListener(t, "tcp4", "127.0.0.1:0")
	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	const scans = 3
	var wg sync.WaitGroup
	start := make(chan struct{})
	for attempt := 1; attempt <= scans; attempt++ {
		wg.Add(1)
		go func(attempt int) {
			defer wg.Done()
			<-start
			results, err := scanner.Scan(ctx, []string{"127.0.0.1"}, []uint16{port})
			if err != nil {
				t.Errorf("scan %d: failed to start: %v", attempt, err)
				return
			}
			count := 0
			for result := range results {
				count++
				if result.State != StateOpen || result.Port != port {
					t.Errorf("scan %d: unexpected result: %+v", attempt, result)
				}
			}
			if count != 1 {
				t.Errorf("scan %d: expected 1 result, got %d", attempt, count)
			}
		}(attempt)
	}
	close(start)
	wg.Wait()
}

func TestScanSlowConsumer(t *testing.T) {
	scanner := newTestScanner(t, 5)
	ports, err := Range(20000, 20199)
	if err != nil {
		t.Fatalf("failed to create port range: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	results, err := scanner.Scan(ctx, []string{"127.0.0.1"}, ports)
	if err != nil {
		t.Fatalf("failed to start scan: %v", err)
	}
	// Let workers block on the unbuffered results channel before consuming.
	time.Sleep(200 * time.Millisecond)
	count := 0
	for range results {
		count++
	}
	if count != len(ports) {
		t.Fatalf("expected %d results, got %d", len(ports), count)
	}
	if err := ctx.Err(); err != nil {
		t.Fatalf("scan did not complete before deadline: %v", err)
	}
}

func TestScanHostnameMultipleIPs(t *testing.T) {
	scanner := newTestScanner(t, 3)
	listener := newTestListener(t, "tcp4", "127.0.0.1:0")
	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	host := "multi.test"
	ips := []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("127.0.0.2")}

	// Use two fixed loopback addresses so the test cannot be skipped on systems
	// whose localhost resolves to just one address.
	scanner.resolveFn = func(ctx context.Context, name string) ([]net.IPAddr, error) {
		if name != host {
			return nil, errors.New("unexpected hostname")
		}
		return []net.IPAddr{{IP: ips[0]}, {IP: ips[1]}}, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	results, err := scanner.Scan(ctx, []string{host}, []uint16{port})
	if err != nil {
		t.Fatalf("failed to start scan: %v", err)
	}

	seen := make(map[string]int)
	for result := range results {
		if result.Host != host || result.Port != port || result.IP == nil {
			t.Fatalf("unexpected multi-IP result: %+v", result)
		}
		seen[result.IP.String()]++
	}
	if len(seen) != len(ips) || seen[ips[0].String()] != 1 || seen[ips[1].String()] != 1 {
		t.Fatalf("expected one result per IP %v, got %v (ctx: %v)", ips, seen, ctx.Err())
	}
	if err := ctx.Err(); err != nil {
		t.Fatalf("scan did not finish before deadline: %v", err)
	}
}

func TestScanDNSResolutionError(t *testing.T) {
	scanner := newTestScanner(t, 3)
	host := "example.test"
	port := uint16(80)
	scanner.resolveFn = func(ctx context.Context, name string) ([]net.IPAddr, error) {
		return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	results, err := scanner.Scan(ctx, []string{host}, []uint16{port})
	if err != nil {
		t.Fatalf("failed to start scan: %v", err)
	}
	count := 0
	for result := range results {
		count++
		if result.Host != host || result.Port != port || result.State != StateError || result.IP != nil {
			t.Fatalf("unexpected DNS failure result: %+v", result)
		}
		var dnsErr *net.DNSError
		if !errors.As(result.Err, &dnsErr) || !dnsErr.IsNotFound {
			t.Fatalf("expected DNS not-found error, got %v", result.Err)
		}
	}
	if count != 1 {
		t.Fatalf("expected 1 DNS error result, got %d", count)
	}
	if err := ctx.Err(); err != nil {
		t.Fatalf("DNS error scan did not complete before deadline: %v", err)
	}
}

func TestScanClosesConnections(t *testing.T) {
	scanner := newTestScanner(t, 1)
	listener := newTestListener(t, "tcp4", "127.0.0.1:0")
	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	results, err := scanner.Scan(ctx, []string{"127.0.0.1"}, []uint16{port})
	if err != nil {
		t.Fatalf("failed to start scan: %v", err)
	}
	if err := listener.(*net.TCPListener).SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("failed to set accept deadline: %v", err)
	}
	conn, err := listener.Accept()
	if err != nil {
		t.Fatalf("failed to accept connection: %v", err)
	}
	defer conn.Close()
	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("failed to set read deadline: %v", err)
	}

	buf := make([]byte, 1)
	_, err = conn.Read(buf)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("expected EOF after scanner closed connection, got %v", err)
	}
	count := 0
	for result := range results {
		count++
		if result.State != StateOpen || result.Port != port {
			t.Fatalf("unexpected result after close: %+v", result)
		}
	}
	if count != 1 {
		t.Fatalf("expected 1 result, got %d", count)
	}
}

func TestScanCancelDuringDNS(t *testing.T) {
	scanner := newTestScanner(t, 3)
	started := make(chan struct{})
	resolverDone := make(chan struct{})
	scanner.resolveFn = func(ctx context.Context, host string) ([]net.IPAddr, error) {
		close(started)
		defer close(resolverDone)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	results, err := scanner.Scan(ctx, []string{"example.test"}, []uint16{80})
	if err != nil {
		t.Fatalf("failed to start scan: %v", err)
	}
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("DNS resolution did not start")
	}
	cancel()
	select {
	case <-resolverDone:
	case <-time.After(2 * time.Second):
		t.Fatal("DNS resolver did not stop after cancellation")
	}
	select {
	case result, ok := <-results:
		if ok {
			t.Fatalf("expected closed results channel, got %+v", result)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("results channel did not close after DNS cancellation")
	}
}

func TestScanNoGoroutineLeaks(t *testing.T) {
	scanner := newTestScanner(t, 4)
	ports, err := Range(20000, 20049)
	if err != nil {
		t.Fatalf("failed to create port range: %v", err)
	}
	started := make(chan struct{}, 4)
	finished := make(chan struct{}, 4)
	scanner.dialFn = func(ctx context.Context, network, address string) (net.Conn, error) {
		started <- struct{}{}
		<-ctx.Done()
		finished <- struct{}{}
		return nil, ctx.Err()
	}

	const rounds = 20
	for round := 1; round <= rounds; round++ {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		results, err := scanner.Scan(ctx, []string{"127.0.0.1"}, ports)
		if err != nil {
			cancel()
			t.Fatalf("round %d: failed to start scan: %v", round, err)
		}
		for i := 0; i < 4; i++ {
			select {
			case <-started:
			case <-ctx.Done():
				cancel()
				t.Fatalf("round %d: expected 4 dial attempts to start, saw %d", round, i)
			}
		}
		cancel()
		timeout := time.After(2 * time.Second)
	drain:
		for {
			select {
			case _, ok := <-results:
				if !ok {
					break drain
				}
			case <-timeout:
				t.Fatalf("round %d: results channel did not close", round)
			}
		}
		for i := 0; i < 4; i++ {
			select {
			case <-finished:
			default:
				t.Fatalf("round %d: dial attempt %d did not finish", round, i+1)
			}
		}
	}
}

func TestScanMultipleHosts(t *testing.T) {
	scanner := newTestScanner(t, 3)
	listener := newTestListener(t, "tcp4", "127.0.0.1:0")
	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	ip := net.ParseIP("127.0.0.1")
	hosts := []string{"host-a.test", "host-b.test"}

	scanner.resolveFn = func(ctx context.Context, host string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: ip}}, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	results, err := scanner.Scan(ctx, hosts, []uint16{port})
	if err != nil {
		t.Fatalf("failed to start scan: %v", err)
	}
	seen := make(map[string]int)
	for result := range results {
		if result.State != StateOpen || result.Port != port || !result.IP.Equal(ip) {
			t.Fatalf("unexpected multi-host result: %+v", result)
		}
		seen[result.Host]++
	}
	if len(seen) != len(hosts) || seen[hosts[0]] != 1 || seen[hosts[1]] != 1 {
		t.Fatalf("expected one result per host %v, got %v", hosts, seen)
	}
	if err := ctx.Err(); err != nil {
		t.Fatalf("multiple-host scan did not finish before deadline: %v", err)
	}
}

func TestScanIPv6(t *testing.T) {
	scanner := newTestScanner(t, 3)
	listener, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback listener unavailable: %v", err)
	}
	defer listener.Close()
	port := uint16(listener.Addr().(*net.TCPAddr).Port)

	conn, err := net.DialTimeout("tcp6", listener.Addr().String(), time.Second)
	if err != nil {
		if runtime.GOOS == "windows" && errors.Is(err, syscall.Errno(10013)) {
			t.Skipf("Windows blocked IPv6 loopback connection: %v", err)
		}
		t.Fatalf("direct IPv6 connection failed without scanner: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("failed to close diagnostic IPv6 connection: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	results, err := scanner.Scan(ctx, []string{"::1"}, []uint16{port})
	if err != nil {
		t.Fatalf("failed to start IPv6 scan: %v", err)
	}
	count := 0
	for result := range results {
		count++
		if result.State != StateOpen || result.Host != "::1" || !result.IP.Equal(net.ParseIP("::1")) || result.Port != port {
			t.Fatalf("unexpected IPv6 result: %+v", result)
		}
	}
	if count != 1 {
		t.Fatalf("expected 1 IPv6 result, got %d", count)
	}
	if err := ctx.Err(); err != nil {
		t.Fatalf("IPv6 scan did not finish before deadline: %v", err)
	}
}
