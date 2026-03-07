package event

import (
	"fmt"
	"time"
)

type Severity int

const (
	Info Severity = iota
	Low
	Medium
	High
	Critical
)

func (s Severity) String() string {
	switch s {
	case Info:
		return "INFO"
	case Low:
		return "LOW"
	case Medium:
		return "MEDIUM"
	case High:
		return "HIGH"
	case Critical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

func (s Severity) Color() string {
	switch s {
	case Info:
		return "\033[36m" // cyan
	case Low:
		return "\033[32m" // green
	case Medium:
		return "\033[33m" // yellow
	case High:
		return "\033[31m" // red
	case Critical:
		return "\033[1;31m" // bold red
	default:
		return "\033[0m"
	}
}

const ColorReset = "\033[0m"

type Event struct {
	Timestamp time.Time
	Source    string         // "process", "network", "filesystem"
	Kind     string         // "new_process", "suspicious_port", "file_modified", etc.
	EntityID string         // unique ID for the tracked entity
	Severity Severity
	Score    float64
	Details  map[string]any
	Message  string
}

func (e Event) Format() string {
	return fmt.Sprintf("%s[%s] [%-8s] %s%s",
		e.Severity.Color(),
		e.Timestamp.Format("2006-01-02 15:04:05"),
		e.Severity.String(),
		e.Message,
		ColorReset,
	)
}

type Bus struct {
	ch chan Event
}

func NewBus(buffer int) *Bus {
	return &Bus{ch: make(chan Event, buffer)}
}

func (b *Bus) Publish(e Event) {
	select {
	case b.ch <- e:
	default:
		// drop event if buffer full — avoid blocking monitors
	}
}

func (b *Bus) Subscribe() <-chan Event {
	return b.ch
}

func (b *Bus) Close() {
	close(b.ch)
}
