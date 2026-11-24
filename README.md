# TCP Port Scanner

A reusable Go package for concurrent **TCP Connect** port scanning. It checks TCP port availability on one or more hosts and streams structured results as they become available.

The package supports IPv4 addresses, IPv6 addresses, and DNS hostnames. It uses the Go standard library and has no third-party dependencies. It is a library, not a command-line application.

## Requirements

- Go **1.25.5**
- Network access to the hosts and ports you want to check

## Installation

From an existing Go module:

```bash
go get github.com/Space4QI/tcp-port-scanner
```

Import the package as `portscan`:

```go
import "github.com/Space4QI/tcp-port-scanner"
```

## Quick start

```go
package main

import (
    "context"
    "fmt"
    "log"
    "time"

    portscan "github.com/Space4QI/tcp-port-scanner"
)

func main() {
    scanner, err := portscan.New(10, 500*time.Millisecond)
    if err != nil {
        log.Fatal(err)
    }

    // Combine individual ports and an inclusive range.
    extraPorts, err := portscan.Range(8000, 8002)
    if err != nil {
        log.Fatal(err)
    }
    ports, err := portscan.MergePorts([]uint16{22, 80, 443}, extraPorts)
    if err != nil {
        log.Fatal(err)
    }

    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()

    results, err := scanner.Scan(ctx, []string{"127.0.0.1", "localhost"}, ports)
    if err != nil {
        log.Fatal(err)
    }

    for result := range results {
        fmt.Printf("%s (%s):%d — %s (%s)\n",
            result.Host, result.IP, result.Port, result.State, result.Duration)
        if result.Err != nil {
            fmt.Printf("  error: %v\n", result.Err)
        }
    }

    if err := ctx.Err(); err != nil {
        log.Printf("scan stopped: %v", err)
    }
}
```

Results can arrive in any order because port checks run concurrently. Each DNS hostname can resolve to multiple IP addresses, producing a separate result for each resolved IP and port.

## Public API

### `New(maxConcurrency int, timeout time.Duration) (*Scanner, error)`

Creates a reusable scanner.

- `maxConcurrency` is the maximum number of simultaneous TCP checks **per `Scan` call**.
- `timeout` is the timeout for a single TCP connection attempt; it is **not** an overall scan deadline.
- Both arguments must be greater than zero, otherwise `New` returns an error.

A `Scanner` can be used for multiple consecutive or concurrent scans. Each concurrent `Scan` call has its own concurrency limit, so the total number of connections across calls can be higher than `maxConcurrency`.

### `Scan(ctx context.Context, hosts []string, ports []uint16) (<-chan Result, error)`

Starts scanning and returns a read-only channel of results.

- Supports IPv4 literals, IPv6 literals, and DNS hostnames.
- Resolves each unique hostname once per scan. If a hostname resolves to multiple IPs, checks each resolved IP for every requested port.
- Trims whitespace and removes exact duplicate host strings and port numbers.
- Returns an immediate error for a nil/already-canceled context, an empty host or port list, an empty host string, or port `0`.
- Returns DNS and TCP connection failures through `Result.Err` in the result stream, rather than as an immediate error from `Scan`.
- Closes the results channel after its workers finish.

**Cancellation and result consumption:** `Scan` uses an unbuffered results channel. The caller should consume the channel until it closes. If the caller stops reading early, it **must cancel the context**; otherwise workers can remain blocked trying to send results. Cancellation stops scheduling further work and may drop pending or in-progress results. Do not assume that every canceled connection generates a `StateCanceled` result.

Use `context.WithTimeout` or `context.WithCancel` to control the overall scan lifetime; the connection timeout configured in `New` applies only to connection attempts.

### `Range(start, end int) ([]uint16, error)`

Creates an inclusive TCP port range. Both endpoints must be between `1` and `65535`, and `start` must not exceed `end`.

```go
ports, err := portscan.Range(20, 25) // 20, 21, 22, 23, 24, 25
```

### `MergePorts(groups ...[]uint16) ([]uint16, error)`

Combines multiple port slices and removes duplicates. Returns an error if the combined list is empty or contains port `0`.

```go
ports, err := portscan.MergePorts([]uint16{22, 80}, []uint16{80, 443})
// ports: []uint16{22, 80, 443}
```

### `MergeHosts(groups ...[]string) ([]string, error)`

Combines multiple host slices, trims leading/trailing whitespace, and removes exact duplicate names. Returns an error if the combined list is empty or contains an empty/whitespace-only hostname.

```go
hosts, err := portscan.MergeHosts([]string{" localhost ", "127.0.0.1"}, []string{"localhost"})
// hosts: []string{"localhost", "127.0.0.1"}
```

## Scan results

Each result contains:

```go
type Result struct {
    Host     string
    IP       net.IP
    Port     uint16
    State    State
    Duration time.Duration
    Err      error
}
```

| Field | Meaning |
| --- | --- |
| `Host` | Original target hostname or address (after whitespace trimming) |
| `IP` | Resolved IP; `nil` when DNS resolution fails |
| `Port` | Checked TCP port |
| `State` | Classified outcome of the check |
| `Duration` | Time spent attempting the TCP connection; zero for DNS resolution failures |
| `Err` | Underlying error when the check fails; `nil` for an open port |

The possible states are:

| State | Meaning |
| --- | --- |
| `StateOpen` (`open`) | TCP connection succeeded |
| `StateClosed` (`closed`) | Connection was refused |
| `StateTimeout` (`timeout`) | Connection attempt timed out |
| `StateUnreachable` (`unreachable`) | Host or network was reported unreachable |
| `StateCanceled` (`canceled`) | An attempted operation was canceled; delivery of canceled results is not guaranteed |
| `StateError` (`error`) | Another error occurred, including most DNS resolution errors |

Connection errors are classified using `errors.Is` / `errors.As`, not by matching error message strings. Actual error states depend on the operating system and network environment.

## Behavior and limitations

- **TCP Connect only:** no SYN, UDP, or raw-socket scanning.
- **No CIDR expansion:** pass individual addresses or hostnames; CIDR input is not expanded.
- **Connection cleanup:** successfully established TCP connections are closed after the port check.
- **No guaranteed ordering:** scan results are streamed as checks finish.
- **IPv6:** supported for regular IPv6 addresses; link-local addresses requiring an interface zone (for example, `fe80::1%eth0`) are not currently handled correctly.
- **DNS errors:** a failed hostname resolution is reported as a result for each requested port, with `IP == nil`, unless scanning is canceled before those results are delivered.

## Tests

Run the complete suite:

```bash
go test -count=1 ./...
```

Run with Go's race detector (required by the assignment):

```bash
go test -count=1 -race ./...
```

Run static analysis:

```bash
go vet ./...
```

On Windows, `-race` requires CGO and a compatible C compiler. An IPv6 loopback integration test may be skipped when the operating system blocks local IPv6 connections.

## Project structure

```text
.
├── go.mod           # Module definition and Go version
├── scanner.go       # Scanner, host/port handling and concurrent scanning
├── result.go        # Result and State definitions
├── scanner_test.go  # Unit and integration tests
└── README.md        # Usage and API documentation
```
