//go:build !linux

package correlator

func FindPIDForFile(path string) []int32 {
	return nil
}
