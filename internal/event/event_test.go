package event

import (
	"testing"
	"time"
)

func TestBusPublishSubscribe(t *testing.T) {
	bus := NewBus(10)
	defer bus.Close()

	e := Event{
		Source:    "process",
		Timestamp: time.Now(),
		Message:   "test event",
	}
	bus.Publish(e)

	ch := bus.Subscribe()
	select {
	case received := <-ch:
		if received.Message != "test event" {
			t.Errorf("expected message 'test event', got %q", received.Message)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("timeout waiting for event")
	}
}

func TestBusBufferFullDropsEvent(t *testing.T) {
	bus := NewBus(2)
	defer bus.Close()

	// Fill the buffer
	bus.Publish(Event{Message: "1"})
	bus.Publish(Event{Message: "2"})

	// This should be dropped (buffer full), not block
	done := make(chan bool, 1)
	go func() {
		bus.Publish(Event{Message: "3"})
		done <- true
	}()

	select {
	case <-done:
		// Good — Publish returned without blocking
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Publish blocked on full buffer")
	}
}

func TestSeverityString(t *testing.T) {
	tests := []struct {
		s    Severity
		want string
	}{
		{Info, "INFO"},
		{Low, "LOW"},
		{Medium, "MEDIUM"},
		{High, "HIGH"},
		{Critical, "CRITICAL"},
	}
	for _, tt := range tests {
		if got := tt.s.String(); got != tt.want {
			t.Errorf("Severity(%d).String() = %q, want %q", tt.s, got, tt.want)
		}
	}
}

func TestEventFormat(t *testing.T) {
	e := Event{
		Severity:  High,
		Timestamp: time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC),
		Message:   "suspicious activity",
	}
	formatted := e.Format()
	if formatted == "" {
		t.Error("Format should return non-empty string")
	}
}
