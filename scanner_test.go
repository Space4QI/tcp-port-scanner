package portscan

import (
	"context"
	"errors"
	"io"
	"net"
	"slices"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	scanner, err := New(0, 1*time.Second)
	if err == nil {
		t.Fatal("expected an error, but got nil")
	}
	if scanner != nil {
		t.Fatal("expected nil scanner, but got non-nil")
	}
}

func TestNewValid(t *testing.T) {
	scanner, err := New(10, time.Second)
	if err != nil {
		t.Fatal("expected nil error, but got non-nil")
	}
	if scanner == nil {
		t.Fatal("expected non-nil scanner, but got nil")
	}
	if scanner.maxConcurrency != 10 {
		t.Fatalf("expected 10, got %d", scanner.maxConcurrency)
	}
	if scanner.timeout != time.Second {
		t.Fatalf("expected time.Second, got %s", scanner.timeout)
	}
}

func TestNewInvalidTimeout(t *testing.T) {
	scanner, err := New(10, 0*time.Second)
	if err == nil {
		t.Fatal("expected an error, but got nil")
	}
	if scanner != nil {
		t.Fatal("expected nil scanner, but got non-nil")
	}
}

func TestValidatePortOpen(t *testing.T) {
	ip := net.ParseIP("127.0.0.1")
	scanner, err := New(10, 1*time.Second)
	if err != nil {
		t.Fatalf("failed to create scanner: %v", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer listener.Close()
	tcpAddr := listener.Addr().(*net.TCPAddr)

	port := uint16(tcpAddr.Port)

	result := scanner.validatePort(context.Background(), "127.0.0.1", port, ip)
	if result.State != StateOpen {
		t.Fatalf("expected state %v, got %v", StateOpen, result.State)
	}
	if !result.IP.Equal(ip) {
		t.Fatalf("address %v are not equal %v", result.IP, ip)
	}
}

func TestValidatePortClosed(t *testing.T) {
	ip := net.ParseIP("127.0.0.1")

	scanner, err := New(10, 1*time.Second)
	if err != nil {
		t.Fatalf("failed to create scanner: %v", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	tcpAddr := listener.Addr().(*net.TCPAddr)

	port := uint16(tcpAddr.Port)

	err = listener.Close()
	if err != nil {
		t.Fatalf("failed to close listener: %v", err)
	}

	result := scanner.validatePort(context.Background(), "127.0.0.1", port, ip)
	if result.State != StateClosed {
		t.Fatalf("expected state %v, got %v, error: %v", StateClosed, result.State, result.Err)
	}
	if result.Err == nil {
		t.Fatalf("expected non-nil error, but got nil")
	}
	if result.Host != "127.0.0.1" {
		t.Fatalf("expected host 127.0.0.1, got %v", result.Host)
	}
	if result.Port != port {
		t.Fatalf("expected port %v, got %v", port, result.Port)
	}
	//if result.Duration <= 0 {
	//	t.Fatalf("expected duration greater 0, got %v", result.Duration)
	//}
}

func TestValidatePortCanceled(t *testing.T) {
	ip := net.ParseIP("127.0.0.1")
	scanner, err := New(10, 1*time.Second)
	if err != nil {
		t.Fatalf("failed to create scanner: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result := scanner.validatePort(ctx, "127.0.0.1", 8080, ip)
	if result.State != StateCanceled {
		t.Fatalf("expected state %v, got %v, error: %v", StateCanceled, result.State, result.Err)
	}
}

func TestValidatePortTimeout(t *testing.T) {
	ip := net.ParseIP("127.0.0.1")
	scanner, err := New(10, 1*time.Second)
	if err != nil {
		t.Fatalf("failed to create scanner: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 0)
	defer cancel()
	result := scanner.validatePort(ctx, "127.0.0.1", 8080, ip)
	if result.State != StateTimeout {
		t.Fatalf("expected state %v, got %v, error: %v", StateTimeout, result.State, result.Err)
	}
}

func TestClassifyError(t *testing.T) {
	result := classifyError(syscall.EHOSTUNREACH)
	if result != StateUnreachable {
		t.Fatalf("expected state %v, got %v", StateUnreachable, result)
	}
	result = classifyError(syscall.ENETUNREACH)
	if result != StateUnreachable {
		t.Fatalf("expected state %v, got %v", StateUnreachable, result)
	}
	result = classifyError(errors.New("unknown error"))
	if result != StateError {
		t.Fatalf("expected state %v, got %v", StateError, result)
	}
	result = classifyError(&net.DNSError{IsTimeout: true})
	if result != StateTimeout {
		t.Fatalf("expected state %v, got %v", StateTimeout, result)
	}
}

func TestResolverHost(t *testing.T) {
	result, err := resolveHost(context.Background(), "127.0.0.1")
	if err != nil {
		t.Fatalf("expected non err, got %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 address, got %v", result)
	}
	ip := result[0].IP
	expectedIP := net.ParseIP("127.0.0.1")
	if !ip.Equal(expectedIP) {
		t.Fatalf("address %v are not equal %v", ip, expectedIP)
	}
}

func TestResolverHostIPv6(t *testing.T) {
	result, err := resolveHost(context.Background(), "::1")
	if err != nil {
		t.Fatalf("expected non err, got %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 address, got %v", result)
	}
	ip := result[0].IP
	expectedIP := net.ParseIP("::1")
	if !ip.Equal(expectedIP) {
		t.Fatalf("address %v are not equal %v", ip, expectedIP)
	}
}

func TestResolverHostName(t *testing.T) {
	result, err := resolveHost(context.Background(), "localhost")
	if err != nil {
		t.Fatalf("expected non err, got %v", err)
	}
	if len(result) == 0 {
		t.Fatalf("expected addresses, got %v", result)
	}
	for _, address := range result {
		ip := address.IP
		if ip == nil {
			t.Fatal("expected non-nil IP, got nil")
		}
	}
}

func TestResolverHostInvalidName(t *testing.T) {
	result, err := resolveHost(context.Background(), "nonexistent.invalid")
	if err == nil {
		t.Fatalf("expected non-nil error, got nil")
	}
	if result != nil {
		t.Fatalf("expected nil addresses, got %v", result)
	}
}

func TestScanHostPort(t *testing.T) {
	scanner, err := New(10, 1*time.Second)
	if err != nil {
		t.Fatalf("failed to create scanner: %v", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	tcpAddr := listener.Addr().(*net.TCPAddr)

	defer listener.Close()

	port := uint16(tcpAddr.Port)

	result, err := scanner.scanHostPort(context.Background(), "127.0.0.1", port)
	if err != nil {
		t.Fatalf("failed to scan host: %v", err)
	}

	if len(result) != 1 {
		t.Fatalf("expected addresses, got %v", result)
	}
	if result[0].State != StateOpen {
		t.Fatalf("expected state %v, got %v", StateOpen, result[0].State)
	}
	expectedIp := net.ParseIP("127.0.0.1")
	if !result[0].IP.Equal(expectedIp) {
		t.Fatalf("address %v are not equal %v", result[0].IP, expectedIp)
	}
}

func TestScanOpenPort(t *testing.T) {
	scanner, err := New(10, 1*time.Second)
	if err != nil {
		t.Fatalf("failed to create scanner: %v", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	tcpAddr := listener.Addr().(*net.TCPAddr)

	defer listener.Close()
	port := uint16(tcpAddr.Port)
	scan, err := scanner.Scan(context.Background(), []string{"127.0.0.1"}, []uint16{port})
	if err != nil {
		t.Fatalf("failed to create scan: %v", err)
	}
	count := 0
	for result := range scan {
		if result.State != StateOpen {
			t.Fatalf("expected state %v, got %v", StateOpen, result.State)
		}
		count++
	}
	if count != 1 {
		t.Fatalf("expected count 1, got %v", count)
	}
}

func TestScanClosedPort(t *testing.T) {
	scanner, err := New(10, 1*time.Second)
	if err != nil {
		t.Fatalf("failed to create scanner: %v", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	tcpAddr := listener.Addr().(*net.TCPAddr)

	if err := listener.Close(); err != nil {
		t.Fatalf("failed to close listener: %v", err)
	}

	port := uint16(tcpAddr.Port)
	scan, err := scanner.Scan(context.Background(), []string{"127.0.0.1"}, []uint16{port})
	if err != nil {
		t.Fatalf("failed to create scan: %v", err)
	}
	count := 0
	for result := range scan {
		if result.State != StateClosed {
			t.Fatalf("expected state %v, got %v", StateClosed, result.State)
		}
		count++
	}
	if count != 1 {
		t.Fatalf("expected count 1, got %v", count)
	}
}

func TestScanMultiplePorts(t *testing.T) {
	scanner, err := New(3, time.Second)
	if err != nil {
		t.Fatalf("failed to create scanner: %v", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer listener.Close()

	listener2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer listener2.Close()

	tcpAddr := listener.Addr().(*net.TCPAddr)
	tcpAddr2 := listener2.Addr().(*net.TCPAddr)

	port := uint16(tcpAddr.Port)
	port2 := uint16(tcpAddr2.Port)
	scan, err := scanner.Scan(context.Background(), []string{"127.0.0.1"}, []uint16{port, port2})
	if err != nil {
		t.Fatalf("failed to create scan: %v", err)
	}
	count := 0
	seen := make(map[uint16]bool)

	for result := range scan {
		if result.State != StateOpen {
			t.Fatalf("expected state %v, got %v", StateOpen, result.State)
		}
		if result.Port != port && result.Port != port2 {
			t.Fatalf("unexpected port: %v", result.Port)
		}
		seen[result.Port] = true
		count++
	}
	if !seen[port] || !seen[port2] {
		t.Fatalf("expected true, got false")
	}
	if count != 2 {
		t.Fatalf("expected count 2, got %v", count)
	}
}

func TestScanManyPorts(t *testing.T) {
	scanner, err := New(10, time.Second)
	if err != nil {
		t.Fatalf("failed to create scanner: %v", err)
	}
	ports, err := Range(10000, 10999)
	if err != nil {
		t.Fatalf("invalid port: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	scan, err := scanner.Scan(ctx, []string{"127.0.0.1"}, ports)
	if err != nil {
		t.Fatalf("failed to create: %v", err)
	}
	count := 0
	for range scan {
		count++
	}
	if count != len(ports) {
		t.Fatalf("expected %d results, got %d", len(ports), count)
	}
}

func TestScanCancellationClosesResults(t *testing.T) {
	scanner, err := New(10, time.Second)
	if err != nil {
		t.Fatalf("failed to create scanner: %v", err)
	}
	ports, err := Range(10000, 10999)
	if err != nil {
		t.Fatalf("invalid port: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	scan, err := scanner.Scan(ctx, []string{"127.0.0.1"}, ports)
	if err != nil {
		t.Fatalf("failed to create: %v", err)
	}
	cancel()
	timeout := time.After(2 * time.Second)

	for {
		select {
		case _, ok := <-scan:
			if !ok {
				return
			}
		case <-timeout:
			t.Fatal("results channel did not close after cancellation")
		}
	}
}

func TestScanCancelWithUnreadResults(t *testing.T) {
	scanner, err := New(1, time.Second)
	if err != nil {
		t.Fatalf("failed to create scanner: %v", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer listener.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tcpAddr := listener.Addr().(*net.TCPAddr)

	port := uint16(tcpAddr.Port)

	scan, err := scanner.Scan(ctx, []string{"127.0.0.1"}, []uint16{port})
	if err != nil {
		t.Fatalf("failed to create: %v", err)
	}
	tcpListener := listener.(*net.TCPListener)
	err = tcpListener.SetDeadline(time.Now().Add(2 * time.Second))
	if err != nil {
		t.Fatalf("failed to set deadline: %v", err)
	}
	conn, err := listener.Accept()
	if err != nil {
		t.Fatalf("failed to set connection: %v", err)
	}
	conn.Close()
	cancel()
	timeout := time.After(2 * time.Second)
	for {
		select {
		case _, ok := <-scan:
			if !ok {
				return
			}
		case <-timeout:
			t.Fatal("results channel did not close after cancellation")
		}
	}
}

func TestScanConcurrencyLimit(t *testing.T) {
	scanner, err := New(3, time.Second)
	if err != nil {
		t.Fatalf("failed to create scanner: %v", err)
	}
	ports, err := Range(10000, 10009)
	if err != nil {
		t.Fatalf("invalid port: %v", err)
	}
	var mu sync.Mutex

	active := 0
	maxActive := 0
	release := make(chan struct{})
	started := make(chan struct{}, 10)

	scanner.dialFn = func(ctx context.Context, network string, address string) (net.Conn, error) {
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
			t.Fatal("3 connections failed to even begin")
		}
	}
	mu.Lock()
	observedMax := maxActive
	mu.Unlock()
	if observedMax != scanner.maxConcurrency {
		t.Fatalf("expected %d count, got %d", scanner.maxConcurrency, observedMax)
	}
	close(release)
	count := 0
	for range results {
		count++
	}
	if count != len(ports) {
		t.Fatalf("expected %d ports, got %d", len(ports), count)
	}
	if maxActive > scanner.maxConcurrency {
		t.Fatalf("concurrency limit exceeded: expected at most %d, got %d", scanner.maxConcurrency, maxActive)
	}
}

func TestScanDuplicateInputs(t *testing.T) {
	scanner, err := New(3, time.Second)
	if err != nil {
		t.Fatalf("failed to create scanner: %v", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer listener.Close()
	port := uint16(listener.Addr().(*net.TCPAddr).Port)

	hosts := []string{"127.0.0.1", "127.0.0.1", "127.0.0.1"}
	ports := []uint16{port, port, port}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	results, err := scanner.Scan(ctx, hosts, ports)
	if err != nil {
		t.Fatalf("failed to start scan: %v", err)
	}

	count := 0
	for result := range results {
		count++

		if result.State != StateOpen || result.Port != port {
			t.Fatalf("unexpected result: %+v", result)
		}
	}
	if count != 1 {
		t.Fatalf("expected 1 result, got %d", count)
	}
}

func TestScanInvalidInputs(t *testing.T) {
	scanner, err := New(3, time.Second)
	if err != nil {
		t.Fatalf("failed to create scanner: %v", err)
	}
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
			name:  "empty context",
			ctx:   nil,
			hosts: []string{"127.0.0.1"},
			ports: []uint16{80},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := scanner.Scan(tt.ctx, tt.hosts, tt.ports)

			if err == nil {
				t.Fatal("expected error, got nil")
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
			wantErr:  false,
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
				t.Fatalf("unexpected error: %v", err)
			}

			if len(ports) != 1 {
				t.Fatalf("expected 1 port, got %d", len(ports))
			}

			if ports[0] != tt.wantPort {
				t.Fatalf("expected port %d, got %d", tt.wantPort, ports[0])
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
				t.Fatalf("unexpected error: %v", err)
			}

			slices.Sort(got)
			slices.Sort(tt.want)

			if !slices.Equal(got, tt.want) {
				t.Fatalf("expected ports %v, got %v", tt.want, got)
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
			name: "merge different hosts",
			groups: [][]string{
				{"127.0.0.1", "localhost"},
				{"192.168.1.1"},
			},
			want: []string{"127.0.0.1", "localhost", "192.168.1.1"},
		},
		{
			name: "remove duplicates",
			groups: [][]string{
				{"127.0.0.1", "localhost"},
				{"localhost", "127.0.0.1"},
			},
			want: []string{"127.0.0.1", "localhost"},
		},
		{
			name: "trim spaces",
			groups: [][]string{
				{" 127.0.0.1 ", " localhost "},
				{"127.0.0.1"},
			},
			want: []string{"127.0.0.1", "localhost"},
		},
		{
			name:    "empty groups",
			groups:  [][]string{},
			wantErr: true,
		},
		{
			name: "empty host",
			groups: [][]string{
				{"127.0.0.1", ""},
			},
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
				t.Fatalf("unexpected error: %v", err)
			}

			slices.Sort(got)
			slices.Sort(tt.want)

			if !slices.Equal(got, tt.want) {
				t.Fatalf("expected hosts %v, got %v", tt.want, got)
			}
		})
	}
}

func TestScanReuse(t *testing.T) {
	scanner, err := New(3, time.Second)
	if err != nil {
		t.Fatalf("failed to create scanner: %v", err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer listener.Close()

	port := uint16(listener.Addr().(*net.TCPAddr).Port)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	for attempt := 1; attempt <= 2; attempt++ {
		results, err := scanner.Scan(
			ctx,
			[]string{"127.0.0.1"},
			[]uint16{port},
		)
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
	scanner, err := New(3, time.Second)
	if err != nil {
		t.Fatalf("failed to create scanner: %v", err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer listener.Close()

	port := uint16(listener.Addr().(*net.TCPAddr).Port)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	const scans = 3

	var wg sync.WaitGroup
	start := make(chan struct{})

	for i := 1; i <= scans; i++ {
		wg.Add(1)

		go func(attempt int) {
			defer wg.Done()

			<-start

			results, err := scanner.Scan(
				ctx,
				[]string{"127.0.0.1"},
				[]uint16{port},
			)
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
		}(i)
	}

	close(start)
	wg.Wait()
}

func TestScanSlowConsumer(t *testing.T) {
	scanner, err := New(5, time.Second)
	if err != nil {
		t.Fatalf("failed to create scanner: %v", err)
	}

	ports, err := Range(20000, 20199)
	if err != nil {
		t.Fatalf("failed to create port range: %v", err)
	}

	ctx, cancel := context.WithTimeout(
		context.Background(),
		10*time.Second,
	)
	defer cancel()

	results, err := scanner.Scan(
		ctx,
		[]string{"127.0.0.1"},
		ports,
	)
	if err != nil {
		t.Fatalf("failed to start scan: %v", err)
	}

	// Simulate a slow consumer
	time.Sleep(200 * time.Millisecond)

	count := 0

	for range results {
		count++
	}

	if count != len(ports) {
		t.Fatalf(
			"expected %d results, got %d",
			len(ports),
			count,
		)
	}

	if err := ctx.Err(); err != nil {
		t.Fatalf("scan did not finish before deadline: %v", err)
	}
}

func TestScanHostnameMultipleIPs(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, "localhost")
	if err != nil {
		t.Fatalf("failed to resolve localhost: %v", err)
	}

	expected := make(map[string]int)
	for _, addr := range addresses {
		expected[addr.IP.String()]++
	}

	if len(expected) < 2 {
		t.Skip("localhost does not resolve to multiple IP addresses")
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer listener.Close()

	port := uint16(listener.Addr().(*net.TCPAddr).Port)

	scanner, err := New(3, time.Second)
	if err != nil {
		t.Fatalf("failed to create scanner: %v", err)
	}

	results, err := scanner.Scan(
		ctx,
		[]string{"localhost"},
		[]uint16{port},
	)
	if err != nil {
		t.Fatalf("failed to start scan: %v", err)
	}

	received := make(map[string]int)

	for result := range results {
		if result.IP == nil {
			t.Fatal("result contains nil IP")
		}

		if result.Host != "localhost" {
			t.Fatalf("unexpected host: %s", result.Host)
		}

		if result.Port != port {
			t.Fatalf("expected port %d, got %d", port, result.Port)
		}

		received[result.IP.String()]++
	}

	if len(received) != len(expected) {
		t.Fatalf("expected IPs %v, got %v", expected, received)
	}

	for ip, count := range expected {
		if received[ip] != count {
			t.Fatalf(
				"IP %s: expected %d results, got %d",
				ip,
				count,
				received[ip],
			)
		}
	}

	if err := ctx.Err(); err != nil {
		t.Fatalf("scan did not finish: %v", err)
	}
}

func TestScanDNSResolutionError(t *testing.T) {
	scanner, err := New(3, time.Second)
	if err != nil {
		t.Fatalf("failed to create scanner: %v", err)
	}

	ctx, cancel := context.WithTimeout(
		context.Background(),
		10*time.Second,
	)
	defer cancel()

	host := "bad..host"
	port := uint16(80)

	results, err := scanner.Scan(
		ctx,
		[]string{host},
		[]uint16{port},
	)
	if err != nil {
		t.Fatalf("failed to start scan: %v", err)
	}

	count := 0

	for result := range results {
		count++

		if result.Host != host {
			t.Fatalf("expected host %s, got %s", host, result.Host)
		}

		if result.Port != port {
			t.Fatalf("expected port %d, got %d", port, result.Port)
		}

		if result.State != StateError {
			t.Fatalf("expected StateError, got %s", result.State)
		}

		if result.Err == nil {
			t.Fatal("expected DNS resolution error, got nil")
		}
	}

	if count != 1 {
		t.Fatalf("expected 1 result, got %d", count)
	}

	if err := ctx.Err(); err != nil {
		t.Fatalf("scan did not finish before deadline: %v", err)
	}
}

func TestScanClosesConnections(t *testing.T) {
	scanner, err := New(1, time.Second)
	if err != nil {
		t.Fatalf("failed to create scanner: %v", err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer listener.Close()

	port := uint16(listener.Addr().(*net.TCPAddr).Port)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	results, err := scanner.Scan(
		ctx,
		[]string{"127.0.0.1"},
		[]uint16{port},
	)
	if err != nil {
		t.Fatalf("failed to start scan: %v", err)
	}

	tcpListener := listener.(*net.TCPListener)
	if err := tcpListener.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("failed to set listener deadline: %v", err)
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
	if err != io.EOF {
		t.Fatalf("expected EOF after scanner closed connection, got %v", err)
	}

	count := 0

	for result := range results {
		count++

		if result.State != StateOpen {
			t.Fatalf("expected StateOpen, got %s", result.State)
		}

		if result.Port != port {
			t.Fatalf("expected port %d, got %d", port, result.Port)
		}
	}

	if count != 1 {
		t.Fatalf("expected 1 result, got %d", count)
	}
}

func TestScanCancelDuringDNS(t *testing.T) {
	scanner, err := New(3, time.Second)
	if err != nil {
		t.Fatalf("failed to create scanner: %v", err)
	}

	started := make(chan struct{})
	resolverDone := make(chan struct{})

	scanner.resolveFn = func(
		ctx context.Context,
		host string,
	) ([]net.IPAddr, error) {
		close(started)
		defer close(resolverDone)

		<-ctx.Done()

		return nil, ctx.Err()
	}

	ctx, cancel := context.WithTimeout(
		context.Background(),
		5*time.Second,
	)
	defer cancel()

	results, err := scanner.Scan(
		ctx,
		[]string{"example.test"},
		[]uint16{80},
	)
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
		t.Fatal("results channel was not closed after cancellation")
	}
}

func TestScanNoGoroutineLeaks(t *testing.T) {
	scanner, err := New(4, time.Second)
	if err != nil {
		t.Fatalf("failed to create scanner: %v", err)
	}

	ports, err := Range(20000, 20049)
	if err != nil {
		t.Fatalf("failed to create port range: %v", err)
	}

	started := make(chan struct{}, 4)
	finished := make(chan struct{}, 4)

	scanner.dialFn = func(
		ctx context.Context,
		network string,
		address string,
	) (net.Conn, error) {
		started <- struct{}{}

		<-ctx.Done()

		finished <- struct{}{}
		return nil, ctx.Err()
	}

	const rounds = 20

	for round := 1; round <= rounds; round++ {
		ctx, cancel := context.WithTimeout(
			context.Background(),
			5*time.Second,
		)

		results, err := scanner.Scan(
			ctx,
			[]string{"127.0.0.1"},
			ports,
		)
		if err != nil {
			cancel()
			t.Fatalf("round %d: failed to start scan: %v", round, err)
		}

		for i := 0; i < 4; i++ {
			select {
			case <-started:
			case <-ctx.Done():
				cancel()
				t.Fatalf("round %d: workers did not start", round)
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
				t.Fatalf(
					"round %d: results channel did not close",
					round,
				)
			}
		}
		
		for i := 0; i < 4; i++ {
			select {
			case <-finished:
			default:
				t.Fatalf(
					"round %d: a dial operation did not finish",
					round,
				)
			}
		}
	}
}
