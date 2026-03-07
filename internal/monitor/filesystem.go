package monitor

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"noctua/internal/config"
	"noctua/internal/event"
)

type fileState struct {
	Hash     string
	ModTime  time.Time
	Size     int64
}

type FileMonitor struct {
	bus      *event.Bus
	cfg      *config.Config
	known    map[string]fileState
	mu       sync.Mutex
	learning bool
}

func NewFileMonitor(bus *event.Bus, cfg *config.Config) *FileMonitor {
	return &FileMonitor{
		bus:      bus,
		cfg:      cfg,
		known:    make(map[string]fileState),
		learning: true,
	}
}

func (fm *FileMonitor) SetLearning(v bool) {
	fm.mu.Lock()
	fm.learning = v
	fm.mu.Unlock()
}

func (fm *FileMonitor) Run(ctx context.Context) {
	// filesystem checks can be less frequent
	interval := time.Duration(fm.cfg.ScanIntervalSec*3) * time.Second
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	fm.scan()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			fm.scan()
		}
	}
}

func (fm *FileMonitor) scan() {
	fm.mu.Lock()
	learning := fm.learning
	fm.mu.Unlock()

	for _, path := range fm.cfg.WatchedPaths {
		info, err := os.Stat(path)
		if err != nil {
			continue // file might not exist, that's ok
		}

		hash, err := hashFile(path)
		if err != nil {
			continue
		}

		current := fileState{
			Hash:    hash,
			ModTime: info.ModTime(),
			Size:    info.Size(),
		}

		fm.mu.Lock()
		prev, exists := fm.known[path]
		fm.known[path] = current
		fm.mu.Unlock()

		if !exists || learning {
			continue
		}

		if prev.Hash != current.Hash {
			fm.bus.Publish(event.Event{
				Timestamp: time.Now(),
				Source:    "filesystem",
				Kind:     "file_modified",
				EntityID:  fmt.Sprintf("file:%s", path),
				Details: map[string]any{
					"path":      path,
					"prev_hash": prev.Hash,
					"new_hash":  current.Hash,
					"prev_size": prev.Size,
					"new_size":  current.Size,
				},
				Message: fmt.Sprintf("File modified: %s (size %d → %d)",
					path, prev.Size, current.Size),
			})
		}
	}
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}
