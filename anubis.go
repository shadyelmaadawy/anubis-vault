package anubis

import (
	"errors"
	"sync"
	"unsafe"
	"github.com/shadyelmaadawy/anubis-vault/internal/crypt"
	"github.com/shadyelmaadawy/anubis-vault/internal/memory"
)

const (
	TAG_SIZE 			= 16
	MAX_BLOCK_SIZE	    = 4096 - TAG_SIZE // Overhead
	MAX_CHACHA_OVERHEAD = 56
)

var (
	ErrVaultInvalid        = errors.New("vault: uninitialized or released vault")
	ErrVaultAlreadySet     = errors.New("vault: data block is already allocated")
	ErrVaultAlreadySealed  = errors.New("vault: data block is already sealed")
	ErrVaultNotSealed      = errors.New("vault: data block must be sealed before use")
	ErrVaultInvalidSize    = errors.New("vault: data size must be between 1 and 4080 bytes")
	ErrVaultAlreadyReleased = errors.New("vault: resources have already been released")
)

// AnubisVault provides a thread-safe, isolated in-memory enclave for sensitive data.
// It pins memory pages in physical RAM, encrypts payloads in-place, and protects cryptographic key material.
type AnubisVault struct {

	mtx      sync.Mutex
	sealed   bool
	
	block    *memory.MemoryBlock
	metadata *memory.MemoryBlock

}

// NewAnubisVault initializes and returns an empty AnubisVault instance.
func NewAnubisVault() *AnubisVault {
	return &AnubisVault{}
}

// Set allocates locked physical memory pages for the payload and cryptographic metadata,
// then copies the provided data into the isolated memory block.
func (v *AnubisVault) Set(data []byte) error {
	v.mtx.Lock()
	defer v.mtx.Unlock()

	var success 	  bool = false
	var dataLength    int = len(data)

	var memoryBlock   memory.MemoryBlock
	var metadataBlock memory.MemoryBlock

	if v.sealed {
		return ErrVaultAlreadySealed
	}

	if v.block != nil || v.metadata != nil {
		return ErrVaultAlreadySet
	}

	if dataLength == 0 || dataLength > MAX_BLOCK_SIZE {
		return ErrVaultInvalidSize
	}


	defer func() {
		if !success {
			for _, b := range []*memory.MemoryBlock{&memoryBlock, &metadataBlock} {
				if b.Address != 0 {
					_ = memory.Erase(b)
					_ = memory.Unlock(b)
					_ = memory.Deallocate(b)
				}
			}
		}
	}()

	for _, item := range []struct {
		block *memory.MemoryBlock
		size  int
	}{
		{&memoryBlock, len(data)},
		{&metadataBlock, MAX_CHACHA_OVERHEAD},
	} {
		if err := memory.Allocate(item.block, item.size); err != nil {
			return err
		}
		if err := memory.Lock(item.block); err != nil {
			return err
		}
	}

	if err := memory.Write(data, &memoryBlock); err != nil {
		return err
	}

	v.block	   = &memoryBlock
	v.metadata = &metadataBlock
	success    = true
	return nil

}

// Seal generates a random XChaCha20 key and nonce, encrypts the payload in-place,
// and protects the key metadata in the Windows kernel using CryptProtectMemory.
func (v *AnubisVault) Seal() error {
	v.mtx.Lock()
	defer v.mtx.Unlock()

	if v.block == nil || v.metadata == nil {
		return ErrVaultInvalid
	}

	if v.sealed {
		return ErrVaultAlreadySealed
	}


	dataBlock := unsafe.Slice((*byte)(unsafe.Pointer(v.block.Address)), v.block.Length + TAG_SIZE)
	metadata  := unsafe.Slice((*byte)(unsafe.Pointer(v.metadata.Address)), v.metadata.Capacity)

	if err := crypt.Fill(metadata); err != nil {
		return err
	}
	key   := metadata[:32]
	nonce := metadata[32:56]

	if err := crypt.Seal(dataBlock[:v.block.Length], key, nonce); err != nil {
		return err
	}
	v.sealed = true

	return memory.Protect(v.metadata)
}

// Release securely zeroes out both data and key memory blocks, unlocks their pages
// from physical RAM, and releases them back to the operating system.
func (v *AnubisVault) Release() error {

	v.mtx.Lock()
	defer v.mtx.Unlock()

	if v.block == nil && v.metadata == nil {
		return ErrVaultAlreadyReleased
	}

	cleanup := func(b *memory.MemoryBlock) error {
		if b == nil || b.Address == 0 {
			return nil
		}
		return errors.Join(
			memory.Erase(b),
			memory.Unlock(b),
			memory.Deallocate(b),
		)
	}

	err := errors.Join(cleanup(v.block), cleanup(v.metadata))

	v.block    = nil
	v.metadata = nil
	v.sealed   = false

	return err
}



// Use temporarily unprotects the key material and decrypts the payload in-place for the
// duration of the callback function. Once fn returns, a fresh nonce is generated and
// the payload and key metadata are immediately re-sealed.
func (v *AnubisVault) Use(fn func([]byte)) error {

	v.mtx.Lock()
	defer v.mtx.Unlock()

	if v.block == nil || v.metadata == nil {
		return ErrVaultInvalid
	}

	if !v.sealed {
		return ErrVaultNotSealed
	}

	if err := memory.Unprotect(v.metadata); err != nil {
		return err
	}
	defer memory.Protect(v.metadata)

	dataBlock := unsafe.Slice((*byte)(unsafe.Pointer(v.block.Address)), v.block.Length + TAG_SIZE)
	metadata  := unsafe.Slice((*byte)(unsafe.Pointer(v.metadata.Address)), v.metadata.Capacity)

	key 	  := metadata[:32]
	nonce 	  := metadata[32:56]

	if err := crypt.Open(dataBlock, key, nonce); err != nil {
		return err
	}

	defer func() {
		_ = crypt.Fill(nonce)
		_ = crypt.Seal(dataBlock[:v.block.Length], key, nonce)
	}()

	fn(dataBlock[:v.block.Length])

	return nil
}
