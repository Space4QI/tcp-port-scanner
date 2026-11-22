package portscan

import (
	"context"
	"errors"
	"fmt"
	"net"
	"runtime"
	"strconv"
	"syscall"
	"time"
)

type Scanner struct {
	maxConcurrency int
	timeout        time.Duration
}

func New(maxConcurrency int, timeout time.Duration) (*Scanner, error) {
	if maxConcurrency <= 0 {
		return nil, errors.New("maxConcurrency must be greater than zero")
	}
	if timeout <= 0 {
		return nil, errors.New("timeout must be greater than zero")
	}
	scanner := Scanner{maxConcurrency: maxConcurrency, timeout: timeout}
	return &scanner, nil
}

func (s *Scanner) validatePort(ctx context.Context, host string, port uint16, ip net.IP) Result {
	dialer := net.Dialer{
		Timeout: s.timeout,
	}
	address := net.JoinHostPort(ip.String(), strconv.Itoa(int(port)))

	start := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", address)
	duration := time.Since(start)
	if err == nil {
		conn.Close()
		return Result{Host: host, Port: port, State: StateOpen, Duration: duration, IP: ip}
	}

	return Result{Host: host, Port: port, State: classifyError(err), Err: err, Duration: duration, IP: ip}
}

func classifyError(err error) State {
	var netErr net.Error

	if errors.Is(err, context.Canceled) {
		return StateCanceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return StateTimeout
	}
	if errors.As(err, &netErr) && netErr.Timeout() {
		return StateTimeout
	}
	if errors.Is(err, syscall.ECONNREFUSED) || (runtime.GOOS == "windows" && errors.Is(err, syscall.Errno(10061))) {
		return StateClosed
	}
	if errors.Is(err, syscall.EHOSTUNREACH) || errors.Is(err, syscall.ENETUNREACH) {
		return StateUnreachable
	}
	return StateError
}

func resolveHost(ctx context.Context, host string) ([]net.IPAddr, error) {
	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf("empty addresses for host %s", host)
	}
	return addresses, nil
}

func (s *Scanner) scanHostPort(ctx context.Context, host string, port uint16) ([]Result, error) {
	addresses, err := resolveHost(ctx, host)
	if err != nil {
		return nil, err
	}
	results := []Result{}
	for _, value := range addresses {
		results = append(results, s.validatePort(ctx, host, port, value.IP))
	}
	return results, nil
}
