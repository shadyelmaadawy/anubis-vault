<p align="center">
  <img width="400" src="./assets/logo.png" alt="AnubisVault Logo">
  <br />
<a>
    <img src="http://img.shields.io/badge/License-MIT-green.svg?style=flat"/> </a> 
<a> 
<a>
    <img src="https://img.shields.io/badge/Platforms-Windows-red?style=flat"/> </a> 
<a> 
<a>
    <img src="https://img.shields.io/badge/Version-0.1.0-yellow?style=flat"/> </a> 
<a> 
<a>
    <img src="https://img.shields.io/badge/Twitter-@shadudiix-blue.svg?style=flat"/> </a> 
<a> 
</p>


# Anubis-Vault
> **⚠️ Early Access (v0.1.0):** 
>This library is currently in active early development. 
>
>This initial release targets **Windows** first, with **Linux support** and more capabilities actively planned for upcoming releases.
> Feedback, issues, and contributions are welcome!

A thread-safe, isolated in-memory enclave written in Go.
**Anubis-Vault** protects sensitive payloads (such as cryptographic keys, tokens, and credentials) from memory dumps, swap/pagefile leaks, and Go Garbage Collector side-effects.


## Security Architecture
* **Physical RAM Pinning:** Keeps sensitive data locked in physical memory so the operating system never writes it to disk.
* **GC Isolation:** Stores data outside the Go Garbage Collector's reach to prevent accidental copies from lingering in memory.
* **Authenticated In-Place Encryption:** Encrypts data directly in memory using **ChaCha20-Poly1305** with automatic nonce rotation on every access.
* **Kernel-Backed Key Protection:** Isolates encryption keys in a separate locked memory block protected by the operating system.


## Roadmap & Upcoming Features

* [ ] **Linux & macOS Support:** Bringing the same memory protection capabilities to Unix-based systems.
* [ ] **Dynamic Payload Sizing:** Support for storing larger data beyond a single memory page.
* [ ] **Built-in Key Derivation:** Helpers to derive vault keys directly from passwords or passphrases.
* [ ] **Extended Benchmarks & Tests:** Deeper performance profiling and cross-platform test coverage.

## Requirements

* **OS:** Windows (x86 / x64) — *Linux support coming soon*
* **Go:** 1.22 or later

## Installation

``````bash
go get github.com/shadyelmaadawy/anubis-vault
``````

## Quick Start

``````go
package main

import (
	"fmt"
	"log"

	anubis "github.com/shadyelmaadawy/anubis-vault"
)

func main() {
	vault := anubis.NewAnubisVault()
	defer vault.Release()

	secret := []byte("super-secret-master-key")

	// Copy payload into locked physical RAM and clear the source slice
	if err := vault.Set(secret); err != nil {
		log.Fatal(err)
	}
	clear(secret)

	// Encrypt payload in-place and protect keys
	if err := vault.Seal(); err != nil {
		log.Fatal(err)
	}

	// Temporarily decrypt for scoped usage (automatically re-sealed afterward)
	err := vault.Use(func(plaintext []byte) {
		fmt.Printf("Decrypted inside enclave: %s\n", string(plaintext))
	})
	if err != nil {
		log.Fatal(err)
	}
}
``````

## API Overview

| Method | Description |
| :--- | :--- |
| ``Set(data []byte)`` | Allocates locked physical pages and copies ``data`` (up to ``4080`` bytes) into unmanaged memory. |
| ``Seal()`` | Generates a random key/nonce, encrypts the payload in-place, and protects key metadata. |
| ``Use(fn func([]byte))`` | Temporarily unprotects keys and decrypts the payload for the callback duration, then rotates the nonce and re-seals. |
| ``Release()`` | Securely zeroes out all memory blocks, unlocks pages, and releases them. 

## To Infinity and beyond!

As an Early Access project, bug reports, security reviews, and feature requests are highly appreciated. 
Feel free to open an issue or submit a pull request on GitHub.

## License

Distributed under the MIT License. See ``LICENSE`` for more information.

## Credits

### Copyright (©) 2024, Shady K. Maadawy, All rights reserved. 
 [@shadudiix](https://github.com/shadyelmaadawy)

