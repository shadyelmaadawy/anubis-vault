//go:build windows

package memory

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"
)

const (
	PAGE_READWRITE					= 0x04

	MEM_COMMIT 	   					= 0x00001000
	MEM_RESERVE    					= 0x00002000

	MEM_RELEASE    					= 0x00008000

	VM_LOCK_1     					= 0x0001

	CRYPTPROTECTMEMORY_BLOCK_SIZE   = 16
	CRYPTPROTECTMEMORY_SAME_PROCESS = 0x00

)

var (
	ErrInvalidSize        = errors.New("memory: allocation size must be greater than zero")
	ErrInvalidBlock       = errors.New("memory: invalid or uninitialized memory block")
	ErrAlreadyDeallocated = errors.New("memory: block has already been deallocated")
	ErrBlockLocked        = errors.New("memory: cannot deallocate a locked memory block")
	ErrAlreadyLocked      = errors.New("memory: block is already locked")
	ErrAlreadyUnlocked    = errors.New("memory: block is already unlocked")
)

var (
	ntdll 						= syscall.NewLazyDLL("ntdll.dll")
	crypt32 				 	= syscall.NewLazyDLL("crypt32.dll")

	procNtAllocateVirtualMemory = ntdll.NewProc("NtAllocateVirtualMemory")
	procNtFreeVirtualMemory     = ntdll.NewProc("NtFreeVirtualMemory")
	
	procRtlZeroMemory 			= ntdll.NewProc("RtlZeroMemory")

	procNtLockVirtualMemory   	= ntdll.NewProc("NtLockVirtualMemory")
	procNtUnlockVirtualMemory 	= ntdll.NewProc("NtUnlockVirtualMemory")

	procCryptProtectMemory   = crypt32.NewProc("CryptProtectMemory")
	procCryptUnprotectMemory = crypt32.NewProc("CryptUnprotectMemory")
)

// Allocate reserves and commits a region of virtual memory with read/write access.
// The actual allocated size may be rounded up to the nearest system page boundary.
func Allocate(block *MemoryBlock, size int) (error) {
	if size <= 0 {
		return ErrInvalidSize
	}

	if err := procNtAllocateVirtualMemory.Find(); err != nil {
		return err
	}
	currentProcessPtr := NtCurrentProcess()
	blockSizePtr 	  := uintptr(size)
	var blockAddrPtr  uintptr

	allocateState, _, _ := procNtAllocateVirtualMemory.Call(
		currentProcessPtr,
		uintptr(unsafe.Pointer(&blockAddrPtr)),
		0,
		uintptr(unsafe.Pointer(&blockSizePtr)),
		MEM_COMMIT|MEM_RESERVE,
		PAGE_READWRITE,
	)
	if !NT_SUCCESS(allocateState) {
		return fmt.Errorf("NtAllocateVirtualMemory, error: 0x%X", allocateState)
	}

	*block = MemoryBlock{
		Address:  blockAddrPtr,
		Capacity: blockSizePtr,
		Length:   0,
	}

	return nil
}

// Deallocate releases a previously allocated virtual memory block back to the OS.
// The block must be unlocked before calling Deallocate.
func Deallocate(block *MemoryBlock) error {
	if block == nil || block.Address == 0 {
		return ErrAlreadyDeallocated
	}

	if block.Locked {
		return ErrBlockLocked
	}

	if err := procNtFreeVirtualMemory.Find(); err != nil {
		return err
	}

	currentProcessPtr := NtCurrentProcess()
	blockAddress 	  := block.Address
	var dumpSizePtr uintptr

	freeState, _, _ := procNtFreeVirtualMemory.Call(
		currentProcessPtr,
		uintptr(unsafe.Pointer(&blockAddress)),
		uintptr(unsafe.Pointer(&dumpSizePtr)),
		MEM_RELEASE,
	)

	if !NT_SUCCESS(freeState) {
		return fmt.Errorf("NtFreeVirtualMemory, error: 0x%X", freeState)
	}

	block.Address = 0
	block.Capacity = 0
	block.Length = 0
	return nil
}

// Write copies the provided byte slice into the allocated memory block.
// It returns an error if the block is invalid or the data exceeds the block's capacity.
func Write(data []byte, block *MemoryBlock) error {

	if block == nil || block.Address == 0 {
		return ErrInvalidBlock
	}

	length    := len(data)
	dataBlock := unsafe.Slice((*byte)(unsafe.Pointer(block.Address)), block.Capacity)

	if length > int(block.Capacity) {
		return errors.New("invalid size")
	}

	copy(dataBlock, data)
	
	block.Length = length

	return nil

}

// Erase securely zeroes out the entire capacity of the memory block using RtlZeroMemory.
func Erase(block *MemoryBlock) error {

	if block == nil || block.Address == 0 {
		return ErrInvalidBlock
	}

	if err := procRtlZeroMemory.Find(); err != nil {
		return err
	}

	procRtlZeroMemory.Call(
		block.Address,
		block.Capacity,
	)

	return nil
}

// Lock pins the allocated virtual memory pages into physical RAM to prevent paging to disk.
func Lock(block *MemoryBlock) error {

	if block == nil || block.Address == 0 {
		return ErrInvalidBlock
	}

	if block.Locked {
		return ErrAlreadyLocked
	}

	if err := procNtLockVirtualMemory.Find(); err != nil {
		return err
	}

	currentProcessPtr := NtCurrentProcess()
	blockAddress 	  := block.Address
	blockCapacity 	  := block.Capacity

	lockState, _, _ := procNtLockVirtualMemory.Call(
		currentProcessPtr,
		uintptr(unsafe.Pointer(&blockAddress)),
		uintptr(unsafe.Pointer(&blockCapacity)),
		VM_LOCK_1,
	)

	if !NT_SUCCESS(lockState) {
		return fmt.Errorf("NtLockVirtualMemory, error: 0x%X", lockState)
	}

	block.Locked = true
	return nil
}

// Unlock unpins previously locked virtual memory pages, allowing the OS to page them to disk again.
func Unlock(block *MemoryBlock) error {
	if block == nil || block.Address == 0 {
		return ErrInvalidBlock
	}

	if !block.Locked {
		return ErrAlreadyUnlocked
	}

	if err := procNtUnlockVirtualMemory.Find(); err != nil {
		return err
	}


	blockAddress 	  := block.Address
	blockCapacity     := block.Capacity
	currentProcessPtr := NtCurrentProcess()

	unLockState, _, _ := procNtUnlockVirtualMemory.Call(
		currentProcessPtr,
		uintptr(unsafe.Pointer(&blockAddress)),
		uintptr(unsafe.Pointer(&blockCapacity)),
		VM_LOCK_1,
	)

	if !NT_SUCCESS(unLockState) {
		return fmt.Errorf("NtUnlockVirtualMemory, error: 0x%X", unLockState)
	}

	block.Locked = false

	return nil
}
// Protect encrypts the memory block in-place using Windows DPAPI (CryptProtectMemory).
// The block's capacity must be a multiple of CRYPTPROTECTMEMORY_BLOCK_SIZE (16 bytes).
func Protect(block *MemoryBlock) error {

	if block == nil || block.Address == 0 {
		return ErrInvalidBlock
	}

	if block.Capacity % CRYPTPROTECTMEMORY_BLOCK_SIZE != 0 {
		return errors.New("invalid block size") 
	}

	if err := procCryptProtectMemory.Find(); err != nil {
		return err
	}

	// dataBlock 			 := unsafe.Slice((*byte)(unsafe.Pointer(block.Address)), block.Capacity)
	protectState, _, err := procCryptProtectMemory.Call(
	block.Address,
        block.Capacity,
		CRYPTPROTECTMEMORY_SAME_PROCESS,
	)
	if protectState == 0 {
		return fmt.Errorf("CryptProtectMemory failed: %w", err)
	}
	return nil
}
// Unprotect decrypts a previously protected memory block in-place using Windows DPAPI (CryptUnprotectMemory).
// The block's capacity must be a multiple of CRYPTPROTECTMEMORY_BLOCK_SIZE (16 bytes).

func Unprotect(block *MemoryBlock) error {
	if block == nil || block.Address == 0 {
		return ErrInvalidBlock
	}

	if block.Length % CRYPTPROTECTMEMORY_BLOCK_SIZE != 0 {
		return errors.New("invalid block size") 
	}

	if err := procCryptUnprotectMemory.Find(); err != nil {
		return err
	}
	// dataBlock			   := unsafe.Slice((*byte)(unsafe.Pointer(block.Address)), block.Capacity)
	unprotectState, _, err := procCryptUnprotectMemory.Call(
	block.Address,
        block.Capacity,
		CRYPTPROTECTMEMORY_SAME_PROCESS,
	)
	if unprotectState == 0 {
		return fmt.Errorf("CryptUnprotectMemory failed: %w", err)
	}

	return nil
}
