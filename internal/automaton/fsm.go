package automaton

import (
	"sync"
	"time"

	"noctua/internal/config"
	"noctua/internal/event"
)

type State int

const (
	Clean State = iota
	Watching
	Suspicious
	Threat
	Blocked
)

func (s State) String() string {
	switch s {
	case Clean:
		return "CLEAN"
	case Watching:
		return "WATCHING"
	case Suspicious:
		return "SUSPICIOUS"
	case Threat:
		return "THREAT"
	case Blocked:
		return "BLOCKED"
	default:
		return "UNKNOWN"
	}
}

type Entity struct {
	ID         string
	Source     string // "process", "network", "filesystem"
	State      State
	Score      float64
	PrevState  State
	FirstSeen  time.Time
	LastEvent  time.Time
	EventCount int
	Details    map[string]any
}

type Transition struct {
	From     State
	To       State
	EntityID string
	Score    float64
}

type Automaton struct {
	mu         sync.RWMutex
	entities   map[string]*Entity
	thresholds config.Thresholds
	transitions chan Transition
}

func New(th config.Thresholds) *Automaton {
	return &Automaton{
		entities:    make(map[string]*Entity),
		thresholds:  th,
		transitions: make(chan Transition, 256),
	}
}

func (a *Automaton) Transitions() <-chan Transition {
	return a.transitions
}

func (a *Automaton) Process(e event.Event) {
	a.mu.Lock()
	defer a.mu.Unlock()

	ent, exists := a.entities[e.EntityID]
	if !exists {
		ent = &Entity{
			ID:        e.EntityID,
			Source:    e.Source,
			State:     Clean,
			FirstSeen: e.Timestamp,
			Details:   make(map[string]any),
		}
		a.entities[e.EntityID] = ent
	}

	ent.Score += e.Score
	ent.LastEvent = e.Timestamp
	ent.EventCount++

	for k, v := range e.Details {
		ent.Details[k] = v
	}

	prev := ent.State
	ent.State = a.classify(ent.Score)

	if ent.State != prev {
		ent.PrevState = prev
		select {
		case a.transitions <- Transition{
			From:     prev,
			To:       ent.State,
			EntityID: ent.ID,
			Score:    ent.Score,
		}:
		default:
		}
	}
}

func (a *Automaton) classify(score float64) State {
	switch {
	case score >= a.thresholds.Blocked:
		return Blocked
	case score >= a.thresholds.Threat:
		return Threat
	case score >= a.thresholds.Suspicious:
		return Suspicious
	case score >= a.thresholds.Watching:
		return Watching
	default:
		return Clean
	}
}

func (a *Automaton) Decay(elapsed time.Duration) {
	a.mu.Lock()
	defer a.mu.Unlock()

	minutes := elapsed.Minutes()
	decay := a.thresholds.DecayPerMin * minutes

	for id, ent := range a.entities {
		if ent.State == Blocked {
			continue // blocked entities don't decay
		}

		prev := ent.State
		ent.Score -= decay
		if ent.Score < 0 {
			ent.Score = 0
		}

		ent.State = a.classify(ent.Score)

		if ent.State != prev {
			ent.PrevState = prev
			select {
			case a.transitions <- Transition{
				From:     prev,
				To:       ent.State,
				EntityID: ent.ID,
				Score:    ent.Score,
			}:
			default:
			}
		}

		// clean up entities that have been clean for a while
		if ent.Score == 0 && time.Since(ent.LastEvent) > 10*time.Minute {
			delete(a.entities, id)
		}
	}
}

func (a *Automaton) GetEntity(id string) *Entity {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if ent, ok := a.entities[id]; ok {
		copy := *ent
		return &copy
	}
	return nil
}

func (a *Automaton) Snapshot() []Entity {
	a.mu.RLock()
	defer a.mu.RUnlock()

	out := make([]Entity, 0, len(a.entities))
	for _, ent := range a.entities {
		out = append(out, *ent)
	}
	return out
}
