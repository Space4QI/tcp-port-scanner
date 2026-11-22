package portscan

import (
	"context"
	"errors"
	"net"
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
