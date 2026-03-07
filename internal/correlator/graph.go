package correlator

import (
	"sync"
	"time"
)

type NodeType string

const (
	NodeProcess    NodeType = "process"
	NodeNetwork    NodeType = "network"
	NodeFilesystem NodeType = "filesystem"
)

type Node struct {
	ID       string
	Type     NodeType
	PID      int32
	Source   string
	Score    float64
	LastSeen time.Time
	Details  map[string]any
}

type EdgeKind string

const (
	EdgeSamePID  EdgeKind = "same_pid"
	EdgePattern  EdgeKind = "pattern"
	EdgeTemporal EdgeKind = "temporal"
)

type Edge struct {
	From    string
	To      string
	Kind    EdgeKind
	Pattern string
	Created time.Time
}

type Graph struct {
	mu       sync.RWMutex
	nodes    map[string]*Node
	edges    []Edge
	pidIndex map[int32][]string // PID → node IDs
}

func NewGraph() *Graph {
	return &Graph{
		nodes:    make(map[string]*Node),
		pidIndex: make(map[int32][]string),
	}
}

func (g *Graph) AddNode(n *Node) {
	g.mu.Lock()
	defer g.mu.Unlock()

	g.nodes[n.ID] = n
	if n.PID != 0 {
		ids := g.pidIndex[n.PID]
		for _, id := range ids {
			if id == n.ID {
				return
			}
		}
		g.pidIndex[n.PID] = append(ids, n.ID)
	}
}

func (g *Graph) AddEdge(e Edge) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.edges = append(g.edges, e)
}

func (g *Graph) NodesByPID(pid int32) []*Node {
	g.mu.RLock()
	defer g.mu.RUnlock()

	ids := g.pidIndex[pid]
	nodes := make([]*Node, 0, len(ids))
	for _, id := range ids {
		if n, ok := g.nodes[id]; ok {
			nodes = append(nodes, n)
		}
	}
	return nodes
}

func (g *Graph) RelatedTo(entityID string) []*Node {
	g.mu.RLock()
	defer g.mu.RUnlock()

	visited := make(map[string]bool)
	var result []*Node
	queue := []string{entityID}
	visited[entityID] = true

	for hop := 0; hop < 3 && len(queue) > 0; hop++ {
		var next []string
		for _, current := range queue {
			for _, e := range g.edges {
				var neighbor string
				if e.From == current {
					neighbor = e.To
				} else if e.To == current {
					neighbor = e.From
				} else {
					continue
				}
				if !visited[neighbor] {
					visited[neighbor] = true
					if n, ok := g.nodes[neighbor]; ok {
						result = append(result, n)
					}
					next = append(next, neighbor)
				}
			}
		}
		queue = next
	}
	return result
}

func (g *Graph) SourceCount(pid int32) int {
	g.mu.RLock()
	defer g.mu.RUnlock()

	sources := make(map[string]bool)
	for _, id := range g.pidIndex[pid] {
		if n, ok := g.nodes[id]; ok {
			sources[n.Source] = true
		}
	}
	return len(sources)
}

func (g *Graph) Prune(maxAge time.Duration) {
	g.mu.Lock()
	defer g.mu.Unlock()

	cutoff := time.Now().Add(-maxAge)
	for id, n := range g.nodes {
		if n.LastSeen.Before(cutoff) {
			delete(g.nodes, id)
			if n.PID != 0 {
				ids := g.pidIndex[n.PID]
				for i, nid := range ids {
					if nid == id {
						g.pidIndex[n.PID] = append(ids[:i], ids[i+1:]...)
						break
					}
				}
				if len(g.pidIndex[n.PID]) == 0 {
					delete(g.pidIndex, n.PID)
				}
			}
		}
	}

	filtered := g.edges[:0]
	for _, e := range g.edges {
		_, fromOK := g.nodes[e.From]
		_, toOK := g.nodes[e.To]
		if fromOK && toOK {
			filtered = append(filtered, e)
		}
	}
	g.edges = filtered
}

type GraphSnapshot struct {
	Nodes []Node `json:"nodes"`
	Edges []Edge `json:"edges"`
}

func (g *Graph) Snapshot() GraphSnapshot {
	g.mu.RLock()
	defer g.mu.RUnlock()

	snap := GraphSnapshot{
		Nodes: make([]Node, 0, len(g.nodes)),
		Edges: make([]Edge, len(g.edges)),
	}
	for _, n := range g.nodes {
		snap.Nodes = append(snap.Nodes, *n)
	}
	copy(snap.Edges, g.edges)
	return snap
}

func (g *Graph) SnapshotForPID(pid int32) GraphSnapshot {
	g.mu.RLock()
	defer g.mu.RUnlock()

	nodeIDs := make(map[string]bool)
	for _, id := range g.pidIndex[pid] {
		nodeIDs[id] = true
	}

	snap := GraphSnapshot{}
	for id := range nodeIDs {
		if n, ok := g.nodes[id]; ok {
			snap.Nodes = append(snap.Nodes, *n)
		}
	}
	for _, e := range g.edges {
		if nodeIDs[e.From] || nodeIDs[e.To] {
			snap.Edges = append(snap.Edges, e)
		}
	}
	return snap
}
