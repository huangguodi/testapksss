//go:build ios

package memory

func GetMemoryInfo(pid int32) (*MemoryInfoStat, error) {
	return nil, ErrNotImplementedError
}
