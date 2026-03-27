package correlator

import (
	"math"
	"strings"
	"sync"
	"time"
)

type PatternMatch struct {
	Name  string
	Bonus float64
}

type PatternMatcher interface {
	Name() string
	Match(nodes []*Node) *PatternMatch
}

// beaconTracker tracks connection timestamps per (PID, remoteIP) for beaconing detection.
type beaconTracker struct {
	mu      sync.Mutex
	records map[beaconKey][]time.Time
}

type beaconKey struct {
	PID      int32
	RemoteIP string
}

func newBeaconTracker() *beaconTracker {
	return &beaconTracker{
		records: make(map[beaconKey][]time.Time),
	}
}

func (bt *beaconTracker) Record(pid int32, remoteIP string, ts time.Time) {
	bt.mu.Lock()
	defer bt.mu.Unlock()

	key := beaconKey{PID: pid, RemoteIP: remoteIP}
	bt.records[key] = append(bt.records[key], ts)

	// keep last 20 entries
	if len(bt.records[key]) > 20 {
		bt.records[key] = bt.records[key][len(bt.records[key])-20:]
	}
}

func (bt *beaconTracker) IsBeaconing(pid int32, remoteIP string) bool {
	bt.mu.Lock()
	defer bt.mu.Unlock()

	key := beaconKey{PID: pid, RemoteIP: remoteIP}
	times := bt.records[key]
	if len(times) < 5 {
		return false
	}

	intervals := make([]float64, 0, len(times)-1)
	for i := 1; i < len(times); i++ {
		intervals = append(intervals, times[i].Sub(times[i-1]).Seconds())
	}

	mean := 0.0
	for _, v := range intervals {
		mean += v
	}
	mean /= float64(len(intervals))

	if mean < 1 {
		return false // too fast, probably scanning not beaconing
	}

	variance := 0.0
	for _, v := range intervals {
		diff := v - mean
		variance += diff * diff
	}
	stddev := math.Sqrt(variance / float64(len(intervals)))

	return stddev < mean*0.15
}

func (bt *beaconTracker) Prune(maxAge time.Duration) {
	bt.mu.Lock()
	defer bt.mu.Unlock()

	cutoff := time.Now().Add(-maxAge)
	for key, times := range bt.records {
		var fresh []time.Time
		for _, t := range times {
			if t.After(cutoff) {
				fresh = append(fresh, t)
			}
		}
		if len(fresh) == 0 {
			delete(bt.records, key)
		} else {
			bt.records[key] = fresh
		}
	}
}

// --- Pattern implementations ---

type reverseShellPattern struct{}

func (p *reverseShellPattern) Name() string { return "reverse_shell" }
func (p *reverseShellPattern) Match(nodes []*Node) *PatternMatch {
	var hasProcess, hasNetwork bool
	var suspiciousPath bool
	var c2Port bool

	suspiciousPaths := []string{"/tmp/", "/var/tmp/", "/dev/shm/", "/.cache/", "/Downloads/"}
	c2Ports := map[uint32]bool{4444: true, 5555: true, 6666: true, 8888: true, 9999: true, 1337: true}

	for _, n := range nodes {
		switch n.Source {
		case "process":
			hasProcess = true
			if exe, ok := n.Details["exe"].(string); ok {
				for _, sp := range suspiciousPaths {
					if strings.Contains(exe, sp) {
						suspiciousPath = true
						break
					}
				}
			}
		case "network":
			hasNetwork = true
			if port, ok := n.Details["remote_port"].(uint32); ok && c2Ports[port] {
				c2Port = true
			}
			if portF, ok := n.Details["remote_port"].(float64); ok && c2Ports[uint32(portF)] {
				c2Port = true
			}
		}
	}

	if hasProcess && hasNetwork && suspiciousPath && c2Port {
		return &PatternMatch{Name: "reverse_shell", Bonus: 40}
	}
	return nil
}

type dataExfiltrationPattern struct{}

func (p *dataExfiltrationPattern) Name() string { return "data_exfiltration" }
func (p *dataExfiltrationPattern) Match(nodes []*Node) *PatternMatch {
	var hasProcess, hasNetwork, hasFS bool
	var sensitiveAccess, highRate bool

	sensitiveFiles := []string{"/etc/shadow", "/etc/passwd", "/etc/sudoers"}

	for _, n := range nodes {
		switch n.Source {
		case "process":
			hasProcess = true
		case "network":
			hasNetwork = true
			if count, ok := n.Details["count"].(int); ok && count > 20 {
				highRate = true
			}
		case "filesystem":
			hasFS = true
			if path, ok := n.Details["path"].(string); ok {
				for _, sf := range sensitiveFiles {
					if path == sf {
						sensitiveAccess = true
						break
					}
				}
			}
		}
	}

	if hasProcess && hasNetwork && hasFS && sensitiveAccess && highRate {
		return &PatternMatch{Name: "data_exfiltration", Bonus: 50}
	}
	return nil
}

type persistencePattern struct{}

func (p *persistencePattern) Name() string { return "persistence" }
func (p *persistencePattern) Match(nodes []*Node) *PatternMatch {
	var hasProcess, hasFS bool
	var persistenceFile bool

	persistFiles := []string{"/etc/crontab", "/etc/ssh/sshd_config", "/etc/sudoers"}

	for _, n := range nodes {
		switch n.Source {
		case "process":
			hasProcess = true
		case "filesystem":
			hasFS = true
			if path, ok := n.Details["path"].(string); ok {
				for _, pf := range persistFiles {
					if path == pf {
						persistenceFile = true
						break
					}
				}
			}
		}
	}

	if hasProcess && hasFS && persistenceFile {
		return &PatternMatch{Name: "persistence", Bonus: 35}
	}
	return nil
}

type lateralMovementPattern struct{}

func (p *lateralMovementPattern) Name() string { return "lateral_movement" }
func (p *lateralMovementPattern) Match(nodes []*Node) *PatternMatch {
	var hasProcess, hasNetwork bool
	var nonSSHToSSH bool

	for _, n := range nodes {
		switch n.Source {
		case "process":
			hasProcess = true
		case "network":
			hasNetwork = true
			port, portOK := n.Details["remote_port"].(uint32)
			if !portOK {
				if pf, ok := n.Details["remote_port"].(float64); ok {
					port = uint32(pf)
					portOK = true
				}
			}
			addr, _ := n.Details["remote_addr"].(string)
			if portOK && port == 22 && isPrivateIP(addr) {
				nonSSHToSSH = true
			}
		}
	}

	if hasProcess && hasNetwork && nonSSHToSSH {
		return &PatternMatch{Name: "lateral_movement", Bonus: 45}
	}
	return nil
}

type cryptoMinerPattern struct{}

func (p *cryptoMinerPattern) Name() string { return "crypto_miner" }
func (p *cryptoMinerPattern) Match(nodes []*Node) *PatternMatch {
	var hasProcess, hasNetwork bool
	var highEntropyName bool

	for _, n := range nodes {
		switch n.Source {
		case "process":
			hasProcess = true
			if name, ok := n.Details["name"].(string); ok && len(name) > 8 {
				if shannonEntropy(name) > 3.5 {
					highEntropyName = true
				}
			}
		case "network":
			hasNetwork = true
		}
	}

	if hasProcess && hasNetwork && highEntropyName {
		return &PatternMatch{Name: "crypto_miner", Bonus: 40}
	}
	return nil
}

type beaconingPattern struct {
	tracker *beaconTracker
}

func (p *beaconingPattern) Name() string { return "beaconing" }
func (p *beaconingPattern) Match(nodes []*Node) *PatternMatch {
	for _, n := range nodes {
		if n.Source != "network" {
			continue
		}
		addr, _ := n.Details["remote_addr"].(string)
		if addr == "" {
			continue
		}
		if p.tracker.IsBeaconing(n.PID, addr) {
			return &PatternMatch{Name: "beaconing", Bonus: 55}
		}
	}
	return nil
}

// spawnLoopPattern fires when the same PID has both a spawn_loop process event
// and a cpu_abuse resource event — the combination indicates a runaway fork.
// Spawn-loop events are identified by the presence of "child_count" in Details;
// cpu_abuse events by the presence of "cpu_pct" in Details.
type spawnLoopPattern struct{}

func (p *spawnLoopPattern) Name() string { return "runaway_fork" }
func (p *spawnLoopPattern) Match(nodes []*Node) *PatternMatch {
	spawnPIDs := make(map[int32]bool)
	cpuPIDs := make(map[int32]bool)

	for _, n := range nodes {
		pid, ok := getPID(n)
		if !ok {
			continue
		}
		if n.Source == "process" {
			if _, hasChildCount := n.Details["child_count"]; hasChildCount {
				spawnPIDs[pid] = true
			}
		}
		if n.Source == "resource" {
			if _, hasCPU := n.Details["cpu_pct"]; hasCPU {
				cpuPIDs[pid] = true
			}
		}
	}

	for pid := range cpuPIDs {
		if spawnPIDs[pid] {
			return &PatternMatch{Name: "runaway_fork", Bonus: 45}
		}
	}
	return nil
}

// sshBruteForcePattern fires when many network connections to port 22 originate
// from many different source PIDs in the correlation window — inbound brute force.
type sshBruteForcePattern struct{}

func (p *sshBruteForcePattern) Name() string { return "ssh_brute_force" }
func (p *sshBruteForcePattern) Match(nodes []*Node) *PatternMatch {
	sshConns := 0
	for _, n := range nodes {
		if n.Source != "network" {
			continue
		}
		port, ok := getPort(n)
		if !ok {
			continue
		}
		if port == 22 {
			sshConns++
		}
	}
	if sshConns >= 5 {
		return &PatternMatch{Name: "ssh_brute_force", Bonus: 55}
	}
	return nil
}

func AllPatterns(tracker *beaconTracker) []PatternMatcher {
	return []PatternMatcher{
		&reverseShellPattern{},
		&dataExfiltrationPattern{},
		&persistencePattern{},
		&lateralMovementPattern{},
		&cryptoMinerPattern{},
		&beaconingPattern{tracker: tracker},
		&spawnLoopPattern{},
		&sshBruteForcePattern{},
	}
}

func getPID(n *Node) (int32, bool) {
	if pid, ok := n.Details["pid"].(int32); ok {
		return pid, true
	}
	if pidf, ok := n.Details["pid"].(float64); ok {
		return int32(pidf), true
	}
	return 0, false
}

func getPort(n *Node) (uint32, bool) {
	if port, ok := n.Details["remote_port"].(uint32); ok {
		return port, true
	}
	if portf, ok := n.Details["remote_port"].(float64); ok {
		return uint32(portf), true
	}
	return 0, false
}

// --- helpers ---

func isPrivateIP(ip string) bool {
	return strings.HasPrefix(ip, "10.") ||
		strings.HasPrefix(ip, "192.168.") ||
		strings.HasPrefix(ip, "172.16.") ||
		strings.HasPrefix(ip, "172.17.") ||
		strings.HasPrefix(ip, "172.18.") ||
		strings.HasPrefix(ip, "172.19.") ||
		strings.HasPrefix(ip, "172.2") ||
		strings.HasPrefix(ip, "172.30.") ||
		strings.HasPrefix(ip, "172.31.")
}

func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]float64)
	for _, c := range s {
		freq[c]++
	}
	length := float64(len([]rune(s)))
	var ent float64
	for _, count := range freq {
		p := count / length
		if p > 0 {
			ent -= p * math.Log2(p)
		}
	}
	return ent
}
