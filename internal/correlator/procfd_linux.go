//go:build linux

package correlator

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func FindPIDForFile(path string) []int32 {
	var pids []int32

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		absPath = path
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}

		fdDir := fmt.Sprintf("/proc/%d/fd", pid)
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}

		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			if strings.HasPrefix(link, absPath) {
				pids = append(pids, int32(pid))
				break
			}
		}
	}
	return pids
}
