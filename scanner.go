package portscan

import (
	"context"
	"errors"
	"fmt"
	"net"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type Scanner struct {
	maxConcurrency int
	timeout        time.Duration
	dialFn         func(context.Context, string, string) (net.Conn, error)
	resolveFn      func(context.Context, string) ([]net.IPAddr, error)
}

type scanJob struct {
	host       string
	port       uint16
	ip         net.IP
	resolveErr error
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
	dial := dialer.DialContext
	if s.dialFn != nil {
		dial = s.dialFn
	}

	address := net.JoinHostPort(ip.String(), strconv.Itoa(int(port)))

	start := time.Now()
	conn, err := dial(ctx, "tcp", address)
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

func Range(start, end int) ([]uint16, error) {
	if start < 1 || start > 65535 || end < 1 || end > 65535 {
		return nil, errors.New("invalid port range")
	}
	if start > end {
		return nil, errors.New("the start port cannot be greater than the end port")
	}
	ports := []uint16{}

	for i := start; i <= end; i++ {
		ports = append(ports, uint16(i))
	}
	return ports, nil
}

func MergePorts(groups ...[]uint16) ([]uint16, error) {
	portsMap := make(map[uint16]bool)
	ports := []uint16{}

	for i := 0; i < len(groups); i++ {
		for j := 0; j < len(groups[i]); j++ {
			port := groups[i][j]
			if port == 0 {
				return nil, errors.New("invalid port")
			}
			if !portsMap[port] {
				ports = append(ports, port)
				portsMap[port] = true
			}
		}
	}

	if len(ports) == 0 {
		return nil, errors.New("empty port list")
	}
	return ports, nil
}

func MergeHosts(groups ...[]string) ([]string, error) {
	hostsMap := make(map[string]bool)
	hosts := []string{}

	for i := 0; i < len(groups); i++ {
		for j := 0; j < len(groups[i]); j++ {
			host := strings.TrimSpace(groups[i][j])
			if host == "" {
				return nil, errors.New("invalid host")
			}
			if !hostsMap[host] {
				hosts = append(hosts, host)
				hostsMap[host] = true
			}
		}
	}

	if len(hosts) == 0 {
		return nil, errors.New("empty host list")
	}
	return hosts, nil
}

func (s *Scanner) Scan(ctx context.Context, hosts []string, ports []uint16) (<-chan Result, error) {
	if ctx == nil {
		return nil, errors.New("context must not be nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	mergeHost, err := MergeHosts(hosts)
	if err != nil {
		return nil, err
	}
	mergePort, err := MergePorts(ports)
	if err != nil {
		return nil, err
	}

	jobs := make(chan scanJob)
	results := make(chan Result)

	resolve := resolveHost
	if s.resolveFn != nil {
		resolve = s.resolveFn
	}

	go func() {
		defer close(jobs)
		for i := 0; i < len(mergeHost); i++ {
			if ctx.Err() != nil {
				return
			}
			addresses, resolveErr := resolve(ctx, mergeHost[i])
			for j := 0; j < len(mergePort); j++ {
				if resolveErr != nil {
					job := scanJob{host: mergeHost[i], port: mergePort[j], resolveErr: resolveErr}
					select {
					case jobs <- job:

					case <-ctx.Done():
						return
					}
					continue
				}

				for k := 0; k < len(addresses); k++ {
					if ctx.Err() != nil {
						return
					}
					job := scanJob{
						host: mergeHost[i],
						port: mergePort[j],
						ip:   addresses[k].IP,
					}
					select {
					case jobs <- job:

					case <-ctx.Done():
						return
					}
				}
			}
		}
	}()

	var wg sync.WaitGroup

	for i := 0; i < s.maxConcurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				if ctx.Err() != nil {
					return
				}
				if job.resolveErr != nil {
					result := Result{Host: job.host, Port: job.port, IP: nil, State: classifyError(job.resolveErr), Err: job.resolveErr}
					select {
					case results <- result:
					case <-ctx.Done():
						return
					}
					continue
				}
				result := s.validatePort(ctx, job.host, job.port, job.ip)
				select {
				case results <- result:
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	return results, nil
}
