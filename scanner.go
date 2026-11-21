package portscan

import (
	"errors"
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
