package correlator

import (
	"testing"
	"time"
)

func TestAddNodeAndLookup(t *testing.T) {
	g := NewGraph()
	n := &Node{ID: "n1", PID: 100, Source: "process", LastSeen: time.Now()}
	g.AddNode(n)

	nodes := g.NodesByPID(100)
	if len(nodes) != 1 {
		t.Fatalf("expected 1 node, got %d", len(nodes))
	}
	if nodes[0].ID != "n1" {
		t.Errorf("expected node n1, got %s", nodes[0].ID)
	}
}

func TestNodesByPIDEmpty(t *testing.T) {
	g := NewGraph()
	nodes := g.NodesByPID(999)
	if len(nodes) != 0 {
		t.Errorf("expected 0 nodes for unknown PID, got %d", len(nodes))
	}
}

func TestSourceCount(t *testing.T) {
	g := NewGraph()
	g.AddNode(&Node{ID: "p1", PID: 100, Source: "process", LastSeen: time.Now()})
	g.AddNode(&Node{ID: "n1", PID: 100, Source: "network", LastSeen: time.Now()})
	g.AddNode(&Node{ID: "f1", PID: 100, Source: "filesystem", LastSeen: time.Now()})

	count := g.SourceCount(100)
	if count != 3 {
		t.Errorf("expected 3 sources, got %d", count)
	}
}

func TestDuplicateNodeID(t *testing.T) {
	g := NewGraph()
	g.AddNode(&Node{ID: "n1", PID: 100, Source: "process", LastSeen: time.Now()})
	g.AddNode(&Node{ID: "n1", PID: 100, Source: "process", LastSeen: time.Now()})

	nodes := g.NodesByPID(100)
	if len(nodes) != 1 {
		t.Errorf("duplicate node should not create duplicate PID index entries, got %d", len(nodes))
	}
}

func TestRelatedToBFS(t *testing.T) {
	g := NewGraph()
	now := time.Now()
	g.AddNode(&Node{ID: "a", PID: 1, Source: "process", LastSeen: now})
	g.AddNode(&Node{ID: "b", PID: 2, Source: "network", LastSeen: now})
	g.AddNode(&Node{ID: "c", PID: 3, Source: "filesystem", LastSeen: now})
	g.AddNode(&Node{ID: "d", PID: 4, Source: "process", LastSeen: now})

	g.AddEdge(Edge{From: "a", To: "b", Kind: EdgeSamePID, Created: now})
	g.AddEdge(Edge{From: "b", To: "c", Kind: EdgePattern, Created: now})
	g.AddEdge(Edge{From: "c", To: "d", Kind: EdgeTemporal, Created: now})

	related := g.RelatedTo("a")
	ids := make(map[string]bool)
	for _, n := range related {
		ids[n.ID] = true
	}

	if !ids["b"] || !ids["c"] || !ids["d"] {
		t.Errorf("BFS 3 hops should find b,c,d; found %v", ids)
	}
}

func TestRelatedToMaxHops(t *testing.T) {
	g := NewGraph()
	now := time.Now()

	// Create chain: a -> b -> c -> d -> e (4 hops)
	for _, id := range []string{"a", "b", "c", "d", "e"} {
		g.AddNode(&Node{ID: id, PID: 1, Source: "process", LastSeen: now})
	}
	g.AddEdge(Edge{From: "a", To: "b", Kind: EdgeSamePID, Created: now})
	g.AddEdge(Edge{From: "b", To: "c", Kind: EdgeSamePID, Created: now})
	g.AddEdge(Edge{From: "c", To: "d", Kind: EdgeSamePID, Created: now})
	g.AddEdge(Edge{From: "d", To: "e", Kind: EdgeSamePID, Created: now})

	related := g.RelatedTo("a")
	ids := make(map[string]bool)
	for _, n := range related {
		ids[n.ID] = true
	}

	// Max 3 hops: should find b(1), c(2), d(3), but NOT e(4)
	if !ids["b"] || !ids["c"] || !ids["d"] {
		t.Errorf("should find b, c, d within 3 hops; found %v", ids)
	}
	if ids["e"] {
		t.Error("should NOT find e at 4 hops")
	}
}

func TestPrune(t *testing.T) {
	g := NewGraph()
	old := time.Now().Add(-20 * time.Minute)
	recent := time.Now()

	g.AddNode(&Node{ID: "old1", PID: 1, Source: "process", LastSeen: old})
	g.AddNode(&Node{ID: "new1", PID: 2, Source: "network", LastSeen: recent})
	g.AddEdge(Edge{From: "old1", To: "new1", Kind: EdgeSamePID, Created: old})

	g.Prune(10 * time.Minute)

	if nodes := g.NodesByPID(1); len(nodes) != 0 {
		t.Error("old node should be pruned")
	}
	if nodes := g.NodesByPID(2); len(nodes) != 1 {
		t.Error("recent node should survive prune")
	}
}
