package portscan

import (
	"net"
	"time"
)

// Result contains the outcome of a single TCP port check.
// IP is nil if DNS resolution fails.
// Err is nil when the connection succeeds.
type Result struct {
	Host     string
	IP       net.IP
	Port     uint16
	State    State
	Duration time.Duration
	Err      error
}

// State represents the outcome of a TCP connection attempt.
type State string

const (
	StateOpen        State = "open"
	StateClosed      State = "closed"
	StateTimeout     State = "timeout"
	StateUnreachable State = "unreachable"
	StateCanceled    State = "canceled"
	StateError       State = "error"
)
