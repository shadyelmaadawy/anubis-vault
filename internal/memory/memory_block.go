package memory

type MemoryBlock struct {
	Address  uintptr
	Capacity uintptr
	Length   int 
	Locked   bool
}


