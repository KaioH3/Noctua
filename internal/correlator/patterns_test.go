package correlator

import (
	"testing"
	"time"
)

func TestReverseShellPattern(t *testing.T) {
	p := &reverseShellPattern{}

	nodes := []*Node{
		{Source: "process", Details: map[string]any{"exe": "/tmp/backdoor"}},
		{Source: "network", Details: map[string]any{"remote_port": uint32(4444)}},
	}
	match := p.Match(nodes)
	if match == nil {
		t.Fatal("expected reverse_shell match")
	}
	if match.Name != "reverse_shell" {
		t.Errorf("expected name reverse_shell, got %s", match.Name)
	}
}

func TestReverseShellNoMatch(t *testing.T) {
	p := &reverseShellPattern{}
	nodes := []*Node{
		{Source: "process", Details: map[string]any{"exe": "/usr/bin/ls"}},
		{Source: "network", Details: map[string]any{"remote_port": uint32(443)}},
	}
	if p.Match(nodes) != nil {
		t.Error("should not match reverse_shell with normal path and port")
	}
}

func TestDataExfiltrationPattern(t *testing.T) {
	p := &dataExfiltrationPattern{}
	nodes := []*Node{
		{Source: "process", Details: map[string]any{}},
		{Source: "network", Details: map[string]any{"count": 25}},
		{Source: "filesystem", Details: map[string]any{"path": "/etc/shadow"}},
	}
	match := p.Match(nodes)
	if match == nil {
		t.Fatal("expected data_exfiltration match")
	}
}

func TestPersistencePattern(t *testing.T) {
	p := &persistencePattern{}
	nodes := []*Node{
		{Source: "process", Details: map[string]any{}},
		{Source: "filesystem", Details: map[string]any{"path": "/etc/crontab"}},
	}
	match := p.Match(nodes)
	if match == nil {
		t.Fatal("expected persistence match")
	}
}

func TestLateralMovementPattern(t *testing.T) {
	p := &lateralMovementPattern{}
	nodes := []*Node{
		{Source: "process", Details: map[string]any{}},
		{Source: "network", Details: map[string]any{"remote_port": uint32(22), "remote_addr": "192.168.1.5"}},
	}
	match := p.Match(nodes)
	if match == nil {
		t.Fatal("expected lateral_movement match")
	}
}

func TestLateralMovementNoMatchPublicIP(t *testing.T) {
	p := &lateralMovementPattern{}
	nodes := []*Node{
		{Source: "process", Details: map[string]any{}},
		{Source: "network", Details: map[string]any{"remote_port": uint32(22), "remote_addr": "8.8.8.8"}},
	}
	if p.Match(nodes) != nil {
		t.Error("should not match lateral_movement with public IP")
	}
}

func TestCryptoMinerPattern(t *testing.T) {
	p := &cryptoMinerPattern{}
	nodes := []*Node{
		{Source: "process", Details: map[string]any{"name": "x7f2k9q3m1p5"}}, // high entropy
		{Source: "network", Details: map[string]any{}},
	}
	match := p.Match(nodes)
	if match == nil {
		t.Fatal("expected crypto_miner match")
	}
}

func TestBeaconingDetection(t *testing.T) {
	bt := newBeaconTracker()
	p := &beaconingPattern{tracker: bt}

	base := time.Now()
	// Record regular intervals (every 60 seconds)
	for i := 0; i < 10; i++ {
		bt.Record(100, "10.0.0.1", base.Add(time.Duration(i)*60*time.Second))
	}

	nodes := []*Node{
		{PID: 100, Source: "network", Details: map[string]any{"remote_addr": "10.0.0.1"}},
	}
	match := p.Match(nodes)
	if match == nil {
		t.Fatal("expected beaconing match for regular intervals")
	}
}

func TestBeaconingNoMatchIrregular(t *testing.T) {
	bt := newBeaconTracker()
	p := &beaconingPattern{tracker: bt}

	base := time.Now()
	// Record highly irregular intervals
	intervals := []int{1, 15, 3, 120, 2, 90, 5, 200, 1, 50}
	elapsed := 0
	for _, gap := range intervals {
		elapsed += gap
		bt.Record(200, "10.0.0.2", base.Add(time.Duration(elapsed)*time.Second))
	}

	nodes := []*Node{
		{PID: 200, Source: "network", Details: map[string]any{"remote_addr": "10.0.0.2"}},
	}
	if p.Match(nodes) != nil {
		t.Error("should not detect beaconing with irregular intervals")
	}
}

func TestBeaconingNotEnoughSamples(t *testing.T) {
	bt := newBeaconTracker()

	base := time.Now()
	// Only 3 samples — below the 5 minimum
	for i := 0; i < 3; i++ {
		bt.Record(100, "10.0.0.1", base.Add(time.Duration(i)*60*time.Second))
	}

	if bt.IsBeaconing(100, "10.0.0.1") {
		t.Error("should not detect beaconing with < 5 samples")
	}
}
