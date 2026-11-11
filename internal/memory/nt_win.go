//go:build windows

package memory

// NtCurrentProcess returns a pseudo-handle (-1) representing the current process.
// It is used with Windows Native API calls (such as NtAllocateVirtualMemory)
// without requiring an explicit OpenProcess handle or closing it afterward.
func NtCurrentProcess() uintptr {
	return ^uintptr(0)
}

// NT_SUCCESS evaluates an NTSTATUS return code and reports whether the system call
// succeeded (status >= 0). Status values are cast to int32 to properly handle
// negative error codes on 64-bit architectures.
func NT_SUCCESS(status uintptr) bool {
	return int32(status) >= 0
}
