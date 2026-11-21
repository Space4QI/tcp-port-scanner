package portscan

import (
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
