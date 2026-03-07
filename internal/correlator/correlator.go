package correlator

import (
	"context"
	"fmt"
	"time"

	"noctua/internal/event"
)

type CorrelationResult struct {
	RelatedNodes []string
	Sources      int
	Multiplier   float64
	Patterns     []PatternMatch
	BonusScore   float64
}

type Correlator struct {
	graph      *Graph
	patterns   []PatternMatcher
	beacon     *beaconTracker
	timeWindow time.Duration
	twoMult    float64
	threeMult  float64
}

func New(timeWindowSec int, twoSourceMult, threeSourceMult float64) *Correlator {
	bt := newBeaconTracker()
	return &Correlator{
		graph:      NewGraph(),
		patterns:   AllPatterns(bt),
		beacon:     bt,
		timeWindow: time.Duration(timeWindowSec) * time.Second,
		twoMult:    twoSourceMult,
		threeMult:  threeSourceMult,
	}
}

func (c *Correlator) Correlate(e *event.Event) *CorrelationResult {
	pid := extractPID(e)

	// Track beaconing for network events
	if e.Source == "network" {
		if addr, ok := e.Details["remote_addr"].(string); ok && addr != "" {
			c.beacon.Record(pid, addr, e.Timestamp)
		}
	}

	node := &Node{
		ID:       e.EntityID,
		Type:     NodeType(e.Source),
		PID:      pid,
		Source:   e.Source,
		Score:    e.Score,
		LastSeen: e.Timestamp,
		Details:  e.Details,
	}
	c.graph.AddNode(node)

	result := &CorrelationResult{Multiplier: 1.0}

	if pid == 0 {
		return result
	}

	// Find related nodes for same PID within time window
	related := c.graph.NodesByPID(pid)
	cutoff := e.Timestamp.Add(-c.timeWindow)

	var recentNodes []*Node
	for _, n := range related {
		if n.ID != e.EntityID && n.LastSeen.After(cutoff) {
			recentNodes = append(recentNodes, n)
			result.RelatedNodes = append(result.RelatedNodes, n.ID)

			// Add edge
			c.graph.AddEdge(Edge{
				From:    e.EntityID,
				To:      n.ID,
				Kind:    EdgeSamePID,
				Created: e.Timestamp,
			})
		}
	}

	// Count distinct sources
	sources := c.graph.SourceCount(pid)
	result.Sources = sources

	switch {
	case sources >= 3:
		result.Multiplier = c.threeMult
	case sources >= 2:
		result.Multiplier = c.twoMult
	}

	// Apply multiplier
	e.Multiplier = result.Multiplier
	e.CorrelatedWith = result.RelatedNodes

	// Include current node for pattern matching
	allNodes := append(recentNodes, node)

	// Run pattern matchers
	for _, pm := range c.patterns {
		if match := pm.Match(allNodes); match != nil {
			result.Patterns = append(result.Patterns, *match)
			result.BonusScore += match.Bonus
			e.Patterns = append(e.Patterns, match.Name)

			// Add pattern edges
			for _, rn := range recentNodes {
				c.graph.AddEdge(Edge{
					From:    e.EntityID,
					To:      rn.ID,
					Kind:    EdgePattern,
					Pattern: match.Name,
					Created: e.Timestamp,
				})
			}
		}
	}

	// Apply correlation scoring
	if result.Multiplier > 1.0 {
		e.Score *= result.Multiplier
	}
	e.Score += result.BonusScore

	return result
}

func (c *Correlator) StartPruning(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.graph.Prune(10 * time.Minute)
			c.beacon.Prune(10 * time.Minute)
		}
	}
}

func (c *Correlator) GraphForPID(pid int32) GraphSnapshot {
	return c.graph.SnapshotForPID(pid)
}

func (c *Correlator) FullSnapshot() GraphSnapshot {
	return c.graph.Snapshot()
}

func extractPID(e *event.Event) int32 {
	switch v := e.Details["pid"].(type) {
	case int32:
		return v
	case int:
		return int32(v)
	case int64:
		return int32(v)
	case float64:
		return int32(v)
	case fmt.Stringer:
		return 0
	default:
		return 0
	}
}
