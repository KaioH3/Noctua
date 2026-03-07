package web

import (
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"time"

	"noctua/internal/automaton"
	"noctua/internal/correlator"
	"noctua/internal/event"
)

//go:embed templates/* static/*
var content embed.FS

const Version = "0.2.0"

type Provider interface {
	RecentEvents() []event.Event
	Entities() []automaton.Entity
	SubscribeSSE() (<-chan event.Event, func())
	Uptime() time.Duration
	ProcessCount() int
	FilesWatched() int
	TotalEvents() int64
	ThreatLevel() string
	ActiveThreats() int
	IsLearning() bool
	CorrelationGraph(pid int32) correlator.GraphSnapshot
	IntelLookup(ip string) map[string]any
	RecordFeedback(entityID, ruleName string, isFalsePositive bool)
	FeedbackStats() map[string]*correlator.FeedbackEntry
	AnomalyTrained() bool
	SigmaRuleCount() int
}

type statsData struct {
	Uptime        time.Duration
	ProcessCount  int
	FilesWatched  int
	TotalEvents   int64
	ActiveThreats int
	ThreatLevel   string
	Learning      bool
	AnomalyReady  bool
	SigmaRules    int
}

type pageData struct {
	Stats    statsData
	Events   []event.Event
	Entities []automaton.Entity
	Platform string
	Version  string
	Learning bool
}

type Server struct {
	provider Provider
	tmpl     *template.Template
	addr     string
}

func NewServer(addr string, provider Provider) (*Server, error) {
	funcMap := template.FuncMap{
		"sevClass": func(s event.Severity) string {
			return strings.ToLower(s.String())
		},
		"stateClass": func(s automaton.State) string {
			return strings.ToLower(s.String())
		},
		"fmtTime": func(t time.Time) string {
			return t.Format("15:04:05")
		},
		"fmtUptime": func(d time.Duration) string {
			h := int(d.Hours())
			m := int(d.Minutes()) % 60
			s := int(d.Seconds()) % 60
			if h > 0 {
				return fmt.Sprintf("%dh %dm %ds", h, m, s)
			}
			if m > 0 {
				return fmt.Sprintf("%dm %ds", m, s)
			}
			return fmt.Sprintf("%ds", s)
		},
		"scorePct": func(score float64) int {
			pct := int(score)
			if pct > 100 {
				pct = 100
			}
			if pct < 0 {
				pct = 0
			}
			return pct
		},
		"truncID": func(s string) string {
			if len(s) <= 30 {
				return s
			}
			return s[:30] + "..."
		},
		"relTime": func(t time.Time) string {
			d := time.Since(t)
			switch {
			case d < time.Second:
				return "now"
			case d < time.Minute:
				return fmt.Sprintf("%ds ago", int(d.Seconds()))
			case d < time.Hour:
				return fmt.Sprintf("%dm ago", int(d.Minutes()))
			default:
				return fmt.Sprintf("%dh ago", int(d.Hours()))
			}
		},
		"hasPatterns": func(e event.Event) bool {
			return len(e.Patterns) > 0
		},
		"hasSigma": func(e event.Event) bool {
			return len(e.SigmaRules) > 0
		},
		"hasIntel": func(e event.Event) bool {
			return len(e.ThreatIntel) > 0
		},
		"anomalyPct": func(score float64) int {
			return int(score * 100)
		},
		"join": func(s []string) string {
			return strings.Join(s, ", ")
		},
		"intelCountry": func(ti map[string]any) string {
			if geo, ok := ti["geoip"].(map[string]any); ok {
				if cc, ok := geo["country_code"].(string); ok {
					return cc
				}
			}
			return ""
		},
	}

	tmplFS, err := fs.Sub(content, "templates")
	if err != nil {
		return nil, fmt.Errorf("template fs: %w", err)
	}

	tmpl, err := template.New("").Funcs(funcMap).ParseFS(tmplFS, "*.html")
	if err != nil {
		return nil, fmt.Errorf("parsing templates: %w", err)
	}

	return &Server{provider: provider, tmpl: tmpl, addr: addr}, nil
}

func (s *Server) Start() error {
	mux := http.NewServeMux()

	staticFS, _ := fs.Sub(content, "static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(staticFS)))

	mux.HandleFunc("GET /{$}", s.handleDashboard)
	mux.HandleFunc("GET /partials/stats", s.handleStatsPartial)
	mux.HandleFunc("GET /partials/entities", s.handleEntitiesPartial)
	mux.HandleFunc("GET /events/stream", s.handleSSE)
	mux.HandleFunc("GET /api/status", s.handleAPIStatus)
	mux.HandleFunc("GET /api/correlations", s.handleCorrelations)
	mux.HandleFunc("GET /api/intel", s.handleIntel)
	mux.HandleFunc("POST /api/feedback", s.handleFeedback)

	fmt.Printf("\033[36m[*] Dashboard: http://localhost%s\033[0m\n", s.addr)
	return http.ListenAndServe(s.addr, mux)
}

func (s *Server) getStats() statsData {
	return statsData{
		Uptime:        s.provider.Uptime(),
		ProcessCount:  s.provider.ProcessCount(),
		FilesWatched:  s.provider.FilesWatched(),
		TotalEvents:   s.provider.TotalEvents(),
		ActiveThreats: s.provider.ActiveThreats(),
		ThreatLevel:   s.provider.ThreatLevel(),
		Learning:      s.provider.IsLearning(),
		AnomalyReady:  s.provider.AnomalyTrained(),
		SigmaRules:    s.provider.SigmaRuleCount(),
	}
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	data := pageData{
		Stats:    s.getStats(),
		Events:   s.provider.RecentEvents(),
		Entities: s.provider.Entities(),
		Platform: runtime.GOOS + "/" + runtime.GOARCH,
		Version:  Version,
		Learning: s.provider.IsLearning(),
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, "page", data); err != nil {
		http.Error(w, err.Error(), 500)
	}
}

func (s *Server) handleStatsPartial(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	s.tmpl.ExecuteTemplate(w, "stats", s.getStats())
}

func (s *Server) handleEntitiesPartial(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	s.tmpl.ExecuteTemplate(w, "entities", s.provider.Entities())
}

func (s *Server) handleSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", 500)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch, cancel := s.provider.SubscribeSSE()
	defer cancel()

	for {
		select {
		case <-r.Context().Done():
			return
		case evt, ok := <-ch:
			if !ok {
				return
			}
			payload := map[string]any{
				"time":         evt.Timestamp.Format("15:04:05"),
				"severity":     strings.ToLower(evt.Severity.String()),
				"label":        evt.Severity.String(),
				"source":       evt.Source,
				"message":      evt.Message,
				"score":        evt.Score,
				"entity":       evt.EntityID,
				"patterns":     evt.Patterns,
				"sigma_rules":  evt.SigmaRules,
				"anomaly_score": evt.AnomalyScore,
				"multiplier":   evt.Multiplier,
			}
			if country := extractCountry(evt.ThreatIntel); country != "" {
				payload["country"] = country
			}
			data, _ := json.Marshal(payload)
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		}
	}
}

func (s *Server) handleAPIStatus(w http.ResponseWriter, r *http.Request) {
	st := s.getStats()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"version":        Version,
		"uptime_seconds": st.Uptime.Seconds(),
		"process_count":  st.ProcessCount,
		"files_watched":  st.FilesWatched,
		"total_events":   st.TotalEvents,
		"active_threats": st.ActiveThreats,
		"threat_level":   st.ThreatLevel,
		"learning":       st.Learning,
		"anomaly_ready":  st.AnomalyReady,
		"sigma_rules":    st.SigmaRules,
	})
}

func (s *Server) handleCorrelations(w http.ResponseWriter, r *http.Request) {
	pidStr := r.URL.Query().Get("pid")
	pid, err := strconv.ParseInt(pidStr, 10, 32)
	if err != nil {
		http.Error(w, "invalid pid parameter", 400)
		return
	}

	graph := s.provider.CorrelationGraph(int32(pid))
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(graph)
}

func (s *Server) handleIntel(w http.ResponseWriter, r *http.Request) {
	ip := r.URL.Query().Get("ip")
	if ip == "" {
		http.Error(w, "missing ip parameter", 400)
		return
	}

	result := s.provider.IntelLookup(ip)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func (s *Server) handleFeedback(w http.ResponseWriter, r *http.Request) {
	var req struct {
		EntityID        string `json:"entity_id"`
		RuleName        string `json:"rule_name"`
		FalsePositive   bool   `json:"false_positive"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", 400)
		return
	}

	s.provider.RecordFeedback(req.EntityID, req.RuleName, req.FalsePositive)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func extractCountry(ti map[string]any) string {
	if ti == nil {
		return ""
	}
	if geo, ok := ti["geoip"].(map[string]any); ok {
		if cc, ok := geo["country_code"].(string); ok {
			return cc
		}
	}
	return ""
}
