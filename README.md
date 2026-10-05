# Rust for Security and Privacy Researchers

Last verified 2026-10-04 · Rust 1.99 · edition 2024

## Table of Contents

1. [Corrected since the 2024 version](#corrected-since-the-2024-version)
2. [Introduction](#introduction)
3. [Memory Safety](#1-memory-safety)
4. [Safe Concurrency](#2-safe-concurrency)
5. [Safe FFI and Interoperability](#3-safe-ffi-and-interoperability)
6. [Security Auditing and Analysis](#4-security-auditing-and-analysis)
7. [Secure Cryptography](#5-secure-cryptography)
8. [Privacy-Preserving Technologies](#6-privacy-preserving-technologies)
9. [Secure Coding Practices in Rust](#7-secure-coding-practices-in-rust)
10. [Secure Networking](#8-secure-networking)
11. [Rust and WebAssembly](#9-rust-and-webassembly)
12. [Rust and Embedded Systems](#10-rust-and-embedded-systems)
13. [Formal Verification](#11-formal-verification)
14. [Case Studies and Real-World Examples](#12-case-studies-and-real-world-examples)
15. [Rust Security Community and Initiatives](#13-rust-security-community-and-initiatives)
16. [Comparison with Other Languages](#14-comparison-with-other-languages)
17. [Security Testing in Rust](#15-security-testing-in-rust)
18. [Secure API Design](#16-secure-api-design)
19. [Troubleshooting Guide](#17-troubleshooting-guide)
20. [Emerging Trends in Rust Security](#18-emerging-trends-in-rust-security)
21. [Conclusion](#conclusion)
22. [Glossary](#glossary)
23. [Additional Resources](#additional-resources)

---

## Corrected since the 2024 version

Earlier versions of this guide gave advice that could make your code less safe. If you followed it, check your code against the fix.

| Old advice | Risk | Fix |
| --- | --- | --- |
| Pin dependencies to exact versions | `=` pins block semver-compatible security fixes and can break resolution | Commit `Cargo.lock`, build with `--locked`, keep caret requirements ([7.5](#75-dependency-management)) |
| Token example: `OsRng`, `% CHARSET.len()`, token printed | Doesn't compile on rand 0.10; modulo bias; secret in logs | `getrandom::fill` plus hex, never logged ([7.3](#73-secure-randomness)) |
| Config example fell back to a default database and printed its URL | Fails open; leaks credentials into logs | Fail closed, never log it; know where env vars leak ([7.4](#74-secure-configuration)) |
| rustls example with `with_safe_defaults` and `webpki` | Pre-0.22 API; `webpki` has had no release since 2023 | rustls ≥0.23.45 with the platform verifier ([8.1](#81-secure-communication-protocols)) |
| "Implement TLS and SSH" yourself | Home-made protocol bugs | Use rustls, russh or snow ([8.1](#81-secure-communication-protocols)) |
| JWT example: hard-coded key, no backend, no iss/aud check, token printed | Forgeable tokens; runtime panic on jsonwebtoken ≥10; tokens in logs | 256-bit key from secret storage, explicit backend, required iss/aud ([8.2](#82-authentication-and-authorization)) |
| "Ownership and type safety extend to FFI boundaries" | Trusting unchecked `extern` signatures | FFI is unchecked: `unsafe extern`, `// SAFETY:` comments ([3.1](#31-foreign-function-interface-ffi)) |
| Raw pointers made with `&num as *const i32` and `&mut num as *mut i32` | Undefined behaviour: Miri flags the read through `r1` | `&raw const` / `&raw mut` ([3.2](#32-unsafe-code)) |
| bindgen run from `main`, output in the working directory | Bindings out of sync with the header; every header item exposed | `build.rs`, `$OUT_DIR`, allowlists ([3.3](#33-bindgen)) |
| C string read with `to_str().unwrap()`, no owner named | Panic on non-UTF-8 input; memory freed by the wrong allocator | Lossy conversion; C memory freed by C ([3.4](#34-ffi-challenges)) |
| "Arc is both Send and Sync"; spawned threads never joined | `Arc<T>` is thread-safe only if `T` is; lost work at exit | `T: Send + Sync`; join every thread ([2.3](#23-send-and-sync-traits)) |
| Debug-redacting newtype credited to "move semantics" | Secret stays readable and is never wiped | `secrecy::SecretString` ([16.1](#161-type-driven-api-design)) |
| `#[error("Internal server error: {0}")]` | Internal error text (paths) sent to clients | Generic message, inner error kept as `source()` ([16.2](#162-error-handling-in-apis)) |
| "Rust prevents XSS" | Skipped output encoding | Escape output, sanitize HTML, deploy CSP ([9.1](#91-wasm-security-benefits)) |
| `cargo audit` as the fix for crypto misuse; RustCrypto "audited and formally verified" | False assurance | Misuse-resistant APIs and review; check each crate's audit scope ([5.2](#52-auditing-and-verification), [17.3](#173-cryptographic-misuse)) |
| Groth16 example with a single-party setup | Whoever ran the setup can forge proofs | Removed; use a multi-party ceremony ([6.1](#61-zero-knowledge-proofs)) |
| Paillier presented as MPC; GG18/GG20-era links | Unmaintained code open to key extraction (BitForge) | Removed; maintained threshold libraries ([6.2](#62-secure-multi-party-computation)) |
| PQClean for post-quantum crypto | Archived; Rust wrapper unmaintained | ml-kem, ml-dsa or rustls's hybrid key exchange ([18.3](#183-post-quantum-cryptography)) |
| Fuzz target that parsed integers with `std` | Tests the standard library, not your code | Fuzz your own decoder with a round-trip check ([15.1](#151-fuzz-testing)) |
| Prusti example as the model for verification | Its contract admitted an overflowing input; Prusti is dormant | Kani and other active verifiers ([11.1](#111-rust-verification-tools)) |
| A libssh2 use-after-free "that Rust would have prevented" | Overstates what Rust prevents | It was libssh CVE-2018-10933, a logic bug ([1.3](#13-lifetimes)) |
| Firecracker's and Tock's isolation credited to Rust | Dropping the other isolation layers | KVM, seccomp and the jailer; Tock's MPU ([12](#12-case-studies-and-real-world-examples)) |

---

## Introduction

Rust is a systems programming language that prioritizes safety, concurrency, and memory efficiency. Its unique features make it an attractive choice for security and privacy-sensitive applications.

This guide covers Rust's security features, where they stop, and best practices for security and privacy researchers. This repository's CI compiles the Rust examples below and runs most of them; the one it skips says why.

---

## 1. Memory Safety

One of Rust's primary strengths is its focus on memory safety. It prevents common memory-related vulnerabilities, such as buffer overflows, null pointer dereferences, and use-after-free errors, through its ownership system and borrow checker.

These guarantees cover safe code, and only while every `unsafe` block you depend on, the standard library and the compiler are sound. A compiler soundness bug open since 2015 ([rust-lang/rust#25860](https://github.com/rust-lang/rust/issues/25860)) lets 100% safe code overflow buffers ([RUSTSEC-2025-0028](https://rustsec.org/advisories/RUSTSEC-2025-0028.html)), so safe Rust is no sandbox for untrusted code. Rust also doesn't prevent logic bugs, deadlocks, leaks or panics, and integer overflow silently wraps in release builds unless you enable `overflow-checks` ([Reference](https://doc.rust-lang.org/reference/behavior-not-considered-unsafe.html), [Cargo profiles](https://doc.rust-lang.org/cargo/reference/profiles.html)).

### 1.1 Ownership

- Each value in Rust has an owner responsible for its memory allocation and deallocation.
- Ownership follows a set of rules:
  - Each value can have only one owner at a time.
  - When the owner goes out of scope, the value is automatically deallocated.
- Ownership prevents issues like double frees and use-after-free vulnerabilities.

**Example:**

```rust
fn main() {
    let s1 = String::from("hello");
    let s2 = s1; // Ownership of the string moves to s2

    // println!("{}", s1); // This would cause a compile-time error
    println!("{}", s2); // This is valid
}
```

### 1.2 Borrowing

- Rust allows borrowing of values through references.
- References come in two forms: shared references (`&T`) and mutable references (`&mut T`).
- The borrow checker enforces the following rules:
  - Either one mutable reference or any number of shared references can exist at a time, but not both simultaneously.
  - References must not outlive the borrowed value.
- Borrowing ensures data race freedom and prevents issues like null pointer dereferences.

**Example:**

```rust
fn main() {
    let mut s = String::from("hello");

    {
        let r1 = &s; // Shared reference
        let r2 = &s; // Another shared reference
        println!("{} and {}", r1, r2);
        // r1 and r2 go out of scope here
    }

    {
        let r3 = &mut s; // Mutable reference
        r3.push_str(", world");
        println!("{}", r3);
        // r3 goes out of scope here
    }
}
```

**Explanation:**

By introducing inner scopes `{ ... }`, we ensure that the immutable references `r1` and `r2` are no longer in use when we create the mutable reference `r3`. This complies with Rust's borrowing rules.

### 1.3 Lifetimes

- Lifetimes express the scope and duration of references.
- Rust's borrow checker uses lifetimes to ensure that references are valid and do not outlive the referenced data.
- Lifetimes prevent dangling references and use-after-free vulnerabilities.

**Example:**

```rust
fn longest<'a>(x: &'a str, y: &'a str) -> &'a str {
    if x.len() > y.len() {
        x
    } else {
        y
    }
}

fn main() {
    let s1 = String::from("short");
    let s2 = String::from("longer");
    let result = longest(s1.as_str(), s2.as_str());
    println!("Longest string: {}", result);
}
```

**Real-World Example:**

In 2018, the libssh server let clients skip authentication: its state machine accepted a client-sent `SSH2_MSG_USERAUTH_SUCCESS` message, so a client could log in with no credentials (CVE-2018-10933, [advisory](https://www.libssh.org/security/advisories/CVE-2018-10933.txt)). That is a logic bug. Ownership and borrowing would not have prevented it; lifetimes stop dangling references, not mistakes in protocol state.

---

## 2. Safe Concurrency

Rust's ownership system and type system enable safe and efficient concurrent programming.

### 2.1 Threads

- Rust provides a standard library for creating and managing threads.
- The `std::thread` module allows spawning new threads and provides synchronization primitives like mutexes and channels.
- Rust's ownership system prevents data races in safe code. It doesn't prevent race conditions or deadlocks ([Nomicon](https://doc.rust-lang.org/nomicon/races.html)).

**Example:**

```rust
use std::thread;

fn main() {
    let handle = thread::spawn(|| {
        for i in 1..10 {
            println!("Thread: number {}", i);
        }
    });

    for i in 1..5 {
        println!("Main: number {}", i);
    }

    handle.join().expect("worker thread panicked");
}
```

### 2.2 Synchronization Primitives

- Rust offers various synchronization primitives in the `std::sync` module.
- Mutexes (`Mutex<T>`) allow exclusive access to shared data. If a thread panics while holding the lock, the mutex is poisoned and later `lock()` calls return `Err` ([Mutex docs](https://doc.rust-lang.org/std/sync/struct.Mutex.html)).
- Read-Write Locks (`RwLock<T>`) provide concurrent read access and exclusive write access.
- Channels (`std::sync::mpsc`) enable safe communication between threads.

**Example using a mutex:**

```rust
use std::sync::{Arc, Mutex};
use std::thread;

fn main() {
    let counter = Arc::new(Mutex::new(0));
    let mut handles = vec![];

    for _ in 0..10 {
        let counter = Arc::clone(&counter);
        let handle = thread::spawn(move || {
            let mut num = counter.lock().expect("mutex poisoned");
            *num += 1;
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().expect("worker thread panicked");
    }

    println!("Result: {}", *counter.lock().expect("mutex poisoned"));
}
```

### 2.3 Send and Sync Traits

- Rust uses the `Send` and `Sync` traits to ensure thread safety of types.
- A type is `Send` if it can be safely transferred between threads.
- A type is `Sync` if it can be safely shared between threads.
- The compiler enforces these traits, preventing potential concurrency bugs.
- `Arc<T>` is `Send` and `Sync` only when `T: Send + Sync`: `Arc<i32>` is both, but `Arc<RefCell<T>>` is neither ([Arc docs](https://doc.rust-lang.org/std/sync/struct.Arc.html)).
- Join the threads you spawn. When `main` returns, the process exits even if other threads are still running ([std::thread](https://doc.rust-lang.org/std/thread/index.html)).

**Example:**

```rust
use std::sync::Arc;
use std::thread;

fn main() {
    let (a, b, c) = (5, String::from("Hello"), vec![1, 2, 3]);
    let h1 = thread::spawn(move || println!("{a}, {b}, {c:?}"));

    // Arc<i32> is Send and Sync because i32 is.
    let arc = Arc::new(42);
    let h2 = thread::spawn(move || println!("{arc}"));

    // Without these joins, main can exit before either thread prints.
    h1.join().expect("thread 1 panicked");
    h2.join().expect("thread 2 panicked");
}
```

`Rc` is not `Send`, so the compiler rejects moving one into another thread (error E0277):

```rust compile_fail E0277
use std::rc::Rc;

fn main() {
    let rc = Rc::new(42);
    let handle = std::thread::spawn(move || println!("{rc}"));
    handle.join().expect("thread panicked");
}
```

For more information on Rust's concurrency features, see the [official documentation](https://doc.rust-lang.org/book/ch16-00-concurrency.html).

---

## 3. Safe FFI and Interoperability

Rust provides mechanisms for interacting with foreign code and systems; keeping each foreign call sound is up to you.

### 3.1 Foreign Function Interface (FFI)

- Rust allows calling functions from other languages (e.g., C) and being called by other languages.
- The `extern` keyword is used to declare external functions and link to foreign libraries.
- The compiler cannot check foreign code. It trusts your `extern` declarations, and a wrong signature is undefined behaviour, so calling a foreign function is `unsafe` and its contract is yours to uphold ([edition guide](https://doc.rust-lang.org/edition-guide/rust-2024/unsafe-extern.html)).
- Since edition 2024, extern blocks must be written `unsafe extern`. Mark an item `safe` only if it is sound for every input: C's `abs(INT_MIN)` is undefined ([POSIX](https://pubs.opengroup.org/onlinepubs/9799919799/functions/abs.html)), so `abs` stays unsafe.

**Example of calling a C function from Rust:**

```rust no_run
use std::ffi::c_int;

// The compiler trusts this signature; it cannot check it against the C library.
unsafe extern "C" {
    fn abs(input: c_int) -> c_int;
}

fn main() {
    // SAFETY: -42 is not INT_MIN, so C's abs is defined for this argument.
    let result = unsafe { abs(-42) };
    println!("Absolute value of -42: {result}");
}
```

### 3.2 Unsafe Code

- Rust allows unsafe code blocks (`unsafe { ... }`) for low-level operations and interacting with foreign code.
- Unsafe code is necessary for certain tasks but should be minimized and carefully reviewed.
- Unsafe code is encapsulated within safe abstractions to maintain overall program safety.

**Example of using unsafe code to dereference a raw pointer:**

```rust
fn main() {
    let mut num = 5;

    // `&raw` creates raw pointers without creating references first.
    let r1 = &raw const num;
    let r2 = &raw mut num;

    // SAFETY: both pointers point to the live local `num`, and no reference
    // to `num` exists while they are used.
    unsafe {
        println!("r1 is: {}", *r1);
        *r2 += 1;
        println!("r2 is: {}", *r2);
    }
}
```

Write `&raw const` / `&raw mut` (Rust 1.82+, [release notes](https://blog.rust-lang.org/2024/10/17/Rust-1.82.0/)), not `&num as *const i32` and `&mut num as *mut i32`: with the casts, creating the `&mut` invalidates `r1`, and Miri reports undefined behaviour at `*r1`. Give every `unsafe` block a `// SAFETY:` comment that states why it is sound.

For more information on unsafe code in Rust, see the [official documentation](https://doc.rust-lang.org/book/ch20-01-unsafe-rust.html).

### 3.3 Bindgen

- [Bindgen](https://github.com/rust-lang/rust-bindgen) is a tool that automatically generates Rust FFI bindings from C/C++ header files.
- It simplifies the process of interfacing with existing libraries and reduces the risk of manual errors.
- Run it from a build script (`build.rs`) with `bindgen` under `[build-dependencies]`, write the output to `$OUT_DIR`, and generate bindings only for the items you use ([bindgen tutorial](https://rust-lang.github.io/rust-bindgen/tutorial-3.html), [allowlists](https://docs.rs/bindgen/0.73.2/bindgen/struct.Builder.html)).

**Example `build.rs` (based on the bindgen tutorial's bzip2 example):**

```rust no_run
use std::{env, path::PathBuf};

fn main() {
    println!("cargo:rustc-link-lib=bz2");

    let bindings = bindgen::Builder::default()
        .header("wrapper.h")
        // Generate only what you call, so every exposed item gets reviewed.
        .allowlist_function("BZ2_.*")
        .allowlist_type("bz_stream")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").expect("Cargo sets OUT_DIR"));
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
```

Load the result in your crate with `include!(concat!(env!("OUT_DIR"), "/bindings.rs"));` ([tutorial](https://rust-lang.github.io/rust-bindgen/tutorial-4.html)).

### 3.4 FFI Challenges

- Check pointers from C for null. `CStr::from_ptr` also needs a NUL-terminated string that doesn't change while you use it, and `to_str()` fails on non-UTF-8 bytes, so don't `unwrap()` it ([CStr docs](https://doc.rust-lang.org/std/ffi/struct.CStr.html)).
- Decide who frees every pointer. Memory allocated by C is freed through C (`free` or the library's own function). A pointer from `CString::into_raw` must come back through `CString::from_raw`, and never goes to C's `free` ([CString docs](https://doc.rust-lang.org/std/ffi/struct.CString.html)).

**Example of safely handling a C string:**

```rust no_run
use std::ffi::{CStr, c_char, c_void};

unsafe extern "C" {
    // Returns a malloc'd copy of `s`, or NULL; the caller frees it with `free`.
    fn strdup(s: *const c_char) -> *mut c_char;
    fn free(ptr: *mut c_void);
}

fn main() {
    // SAFETY: a c"..." literal is NUL-terminated and lives for the whole program.
    let ptr = unsafe { strdup(c"hello from C".as_ptr()) };
    if ptr.is_null() {
        eprintln!("strdup failed");
        return;
    }
    // SAFETY: `ptr` is non-null, NUL-terminated and not freed until below.
    // Copy it out; the lossy conversion can't panic on invalid UTF-8.
    let text = unsafe { CStr::from_ptr(ptr) }.to_string_lossy().into_owned();
    // SAFETY: C allocated `ptr`, so C's `free` releases it, exactly once.
    unsafe { free(ptr.cast()) };
    println!("Received string: {text}");
}
```

---

## 4. Security Auditing and Analysis

Rust's strong type system and ownership model aid in security auditing and analysis.

### 4.1 Type System

- Rust's expressive type system allows encoding invariants and constraints into the types themselves.
- The type system catches many common programming errors at compile-time.
- Rust's enums and pattern matching facilitate secure and exhaustive handling of different cases.

**Example of using enums for secure state handling:**

```rust
enum ConnectionState {
    Disconnected,
    Connecting,
    Connected(String),
    Error(String),
}

fn handle_connection(state: ConnectionState) {
    match state {
        ConnectionState::Disconnected => println!("Not connected"),
        ConnectionState::Connecting => println!("Establishing connection..."),
        ConnectionState::Connected(addr) => println!("Connected to {}", addr),
        ConnectionState::Error(msg) => println!("Connection error: {}", msg),
    }
}

fn main() {
    let states = [
        ConnectionState::Disconnected,
        ConnectionState::Connecting,
        ConnectionState::Connected("192.168.1.1".to_string()),
        ConnectionState::Error("timed out".to_string()),
    ];
    for state in states {
        handle_connection(state);
    }
}
```

### 4.2 Ownership Analysis

- The ownership system provides a clear model of resource management and lifetimes.
- Analyzing ownership and lifetimes helps identify potential security issues and ensures proper resource handling.

### 4.3 Static Analysis Tools

- Rust has a growing ecosystem of static analysis tools that aid in security auditing.
- [Clippy](https://github.com/rust-lang/rust-clippy) is a general linter. Its security value comes mostly from opt-in "restriction" lints such as `undocumented_unsafe_blocks`, `unwrap_used`, `indexing_slicing`, `arithmetic_side_effects` and `as_conversions` ([lint list](https://rust-lang.github.io/rust-clippy/stable/index.html)).
- [rust-analyzer](https://github.com/rust-lang/rust-analyzer) is an IDE language server, not a vulnerability scanner. It assumes all code is trusted and runs a project's build scripts and proc macros when you open it, so open untrusted repositories only in a disposable VM or with it disabled ([security notes](https://rust-analyzer.github.io/book/security.html)).
- These tools complement manual code review and help catch potential security flaws early in the development process.

**Example of using Clippy with some restriction lints:**

```bash
cargo clippy -- -W clippy::undocumented_unsafe_blocks -W clippy::unwrap_used -W clippy::indexing_slicing
```

### 4.4 Limitations and Complementary Approaches

- While static analysis tools are valuable, they have limitations and blind spots.
- It's important to complement static analysis with manual code review and dynamic analysis techniques.
- Combining multiple analysis approaches ensures a more thorough security audit.

---

## 5. Secure Cryptography

Rust has a robust ecosystem of cryptographic libraries that prioritize security and correctness.

### 5.1 RustCrypto

- [RustCrypto](https://github.com/RustCrypto) is a collection of high-quality cryptographic algorithms and primitives implemented in Rust.
- It provides a wide range of cryptographic functionalities, including symmetric and asymmetric encryption, hashing, and digital signatures.
- RustCrypto libraries are designed with a focus on security, performance, and usability.

**Example of using RustCrypto for SHA-256 hashing:**

```rust
use sha2::{Digest, Sha256};

fn main() {
    let digest = Sha256::digest(b"hello world");
    // sha2 0.11 digests don't implement LowerHex, so hex-encode them.
    println!("SHA-256 hash: {}", hex::encode(digest));
}
```

### 5.2 Auditing and Verification

- Check each crate's audit scope before you rely on it. Only a few RustCrypto crates have third-party audits: NCC Group audited aes-gcm and chacha20poly1305 in 2020, and k256 and crypto-bigint; Include Security audited rsa ([aes-gcm](https://github.com/RustCrypto/AEADs/blob/master/aes-gcm/README.md), [k256](https://github.com/RustCrypto/elliptic-curves/blob/master/k256/README.md), [rsa](https://github.com/RustCrypto/RSA/blob/master/README.md)).
- Others say they have never been independently audited, including ml-kem, ml-dsa, p256 and ecdsa ([ml-kem](https://github.com/RustCrypto/KEMs/blob/master/ml-kem/README.md), [p256](https://github.com/RustCrypto/elliptic-curves/blob/master/p256/README.md)). RustCrypto crates are not formally verified ([rustls-rustcrypto](https://github.com/RustCrypto/rustls-rustcrypto/blob/master/README.md)).
- `rsa` is vulnerable to the Marvin timing attack, which can recover private keys, and has no patched release ([RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071.html)).
- Memory safety doesn't stop side channels: LLVM inserted a branch into curve25519-dalek's scalar subtraction, a timing leak fixed in 4.1.3 ([RUSTSEC-2024-0344](https://rustsec.org/advisories/RUSTSEC-2024-0344.html)).

For more information on secure cryptography in Rust, see the [RustCrypto repository](https://github.com/RustCrypto) and the [Rust Cryptography Libraries](https://lib.rs/cryptography) on Lib.rs.

---

## 6. Privacy-Preserving Technologies

Rust's safety guarantees and performance make it well-suited for implementing privacy-preserving technologies.

### 6.1 Zero-Knowledge Proofs

- Zero-Knowledge Proofs (ZKPs) allow proving statements without revealing additional information.
- Rust's safety and performance characteristics make it a good choice for implementing ZKP systems.
- Libraries like [Bellman](https://github.com/zkcrypto/bellman) and [Arkworks](https://github.com/arkworks-rs) provide building blocks for constructing ZKP circuits and protocols. Arkworks describes itself as an academic prototype that is not ready for production ([ark-groth16](https://github.com/arkworks-rs/groth16)).
- Under-constrained circuits are the most common vulnerability class in real ZK circuits, and Rust's type system doesn't catch them ([SoK of 141 SNARK bugs](https://arxiv.org/abs/2402.15293)).
- Groth16 needs a trusted setup. Whoever runs bellman's `generate_random_parameters` samples the setup secret ("toxic waste") and can forge proofs ([generator source](https://github.com/zkcrypto/bellman/blob/main/groth16/src/generator.rs)), so production parameters come from a multi-party ceremony, which is safe if at least one participant deletes their share. [halo2](https://github.com/zcash/halo2) needs no trusted setup.

### 6.2 Secure Multi-Party Computation

- Secure Multi-Party Computation (MPC) allows multiple parties to jointly compute a function without revealing their inputs.
- For threshold Schnorr signatures, use [ZcashFoundation/frost](https://github.com/ZcashFoundation/frost) (FROST, RFC 9591). For threshold ECDSA, use [cggmp24](https://github.com/LFDT-Lockness/cggmp21) 0.7.0-alpha.2 or later: its patched releases are pre-releases, which Cargo selects only when the version requirement names a pre-release, such as `cggmp24 = "0.7.0-alpha.3"` ([RUSTSEC-2025-0130](https://rustsec.org/advisories/RUSTSEC-2025-0130.html), [Cargo Book](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html)).
- Avoid GG18/GG20 implementations such as ZenGo-X's multi-party-ecdsa. It is unmaintained and unpatched for BitForge (CVE-2023-33241), where a malicious party extracts the full key ([Fireblocks report](https://www.fireblocks.com/blog/gg18-and-gg20-paillier-key-vulnerability-technical-report)). RustSec has no advisory for it, so `cargo audit` won't warn you.
- Paillier is additively homomorphic encryption, not an MPC protocol. Protocols such as GG18/GG20 use it as a building block, and each party's Paillier key needs a zero-knowledge proof that it is well formed.

### 6.3 Homomorphic Encryption

- Homomorphic Encryption (HE) enables computations on encrypted data without decryption.
- [tfhe-rs](https://github.com/zama-ai/tfhe-rs) (crate `tfhe`) is Zama's Rust FHE library. Its BSD-3-Clause-Clear licence allows free use only for development, research, prototyping and experimentation; commercial use needs Zama's patent licence. Its README also states the security target of its default parameters (IND-CPA^D) and that it doesn't yet mitigate side channels.
- [Concrete](https://github.com/zama-ai/concrete) is Zama's TFHE compiler for Python; from Rust, use tfhe-rs.

---

## 7. Secure Coding Practices in Rust

Rust's design encourages secure coding practices, but it's still important to follow best practices and be mindful of potential pitfalls.

### 7.1 Input Validation and Sanitization

- Validate external input against what you expect (an allowlist) and reject the rest. Use Rust's types to keep validated and unvalidated data apart.
- Validation alone doesn't stop injection. Keep data out of code: bind SQL parameters (sqlx `bind`, `QueryBuilder::push_bind`) instead of formatting queries ([QueryBuilder docs](https://docs.rs/sqlx/0.9.0/sqlx/struct.QueryBuilder.html)), and escape output for HTML ([9.1](#91-wasm-security-benefits)).
- Be cautious when using unsafe code or interacting with untrusted data.

**Example of input validation:**

```rust
use regex::Regex;
use std::sync::LazyLock;

// Compiled once. The pattern is a constant, so a failure here is a bug, not bad input.
static USERNAME: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-zA-Z0-9_]{3,20}$").expect("valid regex"));

fn validate_username(username: &str) -> bool {
    USERNAME.is_match(username)
}

fn main() {
    assert!(validate_username("john_doe123"));
    assert!(!validate_username("user@name"));
}
```

### 7.2 Error Handling

- Use Rust's error handling mechanisms, such as `Result` and `Option`, to explicitly handle errors and prevent unexpected behavior.
- Avoid unwrapping (`unwrap()`) or ignoring (`_`) errors, as this can lead to runtime panics or silent failures.
- Propagate errors to the caller or handle them gracefully to maintain program stability.

**Example of proper error handling:**

```rust
use std::fs::File;
use std::io::{self, Read};

fn read_file_contents(path: &str) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    Ok(contents)
}

fn main() {
    match read_file_contents("example.txt") {
        Ok(contents) => println!("File contents: {}", contents),
        Err(e) => eprintln!("Error reading file: {}", e),
    }
}
```

### 7.3 Secure Randomness

- Use cryptographically secure random number generators for security-sensitive operations. For keys and tokens, take bytes straight from the operating system with `getrandom::fill` ([getrandom](https://github.com/rust-random/getrandom)).
- rand 0.10 renamed its API: `OsRng` is now `SysRng`, `RngCore` is now `Rng`, and the old `Rng` is now `RngExt`, so `rand::Rng` now means the core trait ([rand 0.10 update guide](https://rust-random.github.io/book/update-0.10.html)).
- Don't map random numbers onto a character set with `%`: unless the set's size divides the generator's range, some characters come up more often (modulo bias). Encode random bytes as hex or base64 instead.
- Never print or log tokens.

**Example of using secure randomness:**

```rust
/// A 256-bit token from the OS random number generator, hex-encoded.
fn generate_secure_token() -> Result<String, getrandom::Error> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes)?;
    Ok(hex::encode(bytes))
}

fn main() -> Result<(), getrandom::Error> {
    let token = generate_secure_token()?;
    // Hand the token to its owner; never print or log it.
    assert_eq!(token.len(), 64);
    Ok(())
}
```

### 7.4 Secure Configuration

- Store sensitive configuration data, such as API keys and passwords, securely.
- Keep secrets out of source code; prefer a secret manager. Environment variables leak: child processes inherit them unless you call `Command::env_clear` or `env_remove` ([Command docs](https://doc.rust-lang.org/std/process/struct.Command.html)), `/proc/<pid>/environ` keeps the startup values even after `remove_var` ([proc_pid_environ(5)](https://man7.org/linux/man-pages/man5/proc_pid_environ.5.html)), and core dumps contain them ([core(5)](https://man7.org/linux/man-pages/man5/core.5.html)).
- Fail closed: if a required setting is missing, refuse to start instead of using a default. Never log secrets or URLs that contain them.
- To load a `.env` file, use `dotenvy`; `dotenv` is unmaintained ([RUSTSEC-2021-0141](https://rustsec.org/advisories/RUSTSEC-2021-0141.html)).
- Regularly rotate and update secrets to minimize the impact of potential breaches.

**Example of reading configuration from the environment:**

```rust no_run
use std::{env, process};

fn main() {
    // Fail closed: refuse to start instead of falling back to a default database.
    let Ok(db_url) = env::var("DATABASE_URL") else {
        eprintln!("DATABASE_URL is missing or not valid UTF-8");
        process::exit(1);
    };
    // Never log `db_url`: connection strings usually embed credentials.
    connect(&db_url);
}

fn connect(_db_url: &str) {
    // Open your connection pool here.
}
```

### 7.5 Dependency Management

- Keep dependencies up to date to ensure you have the latest security patches and bug fixes.
- Regularly check dependencies against the RustSec Advisory Database using tools like [`cargo-audit`](https://github.com/RustSec/rustsec/tree/main/cargo-audit) or [`cargo deny check advisories`](https://github.com/EmbarkStudios/cargo-deny).
- Don't pin exact versions (`=1.2.3`) in `Cargo.toml`: exact pins block semver-compatible fixes and can make resolution fail. For reproducible builds, commit `Cargo.lock` and build with `--locked`; keep default caret requirements, and test against the latest versions on a schedule, for example a CI job that runs `cargo update`, Dependabot or Renovate ([Cargo Book](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html), [Cargo team](https://blog.rust-lang.org/2023/08/29/committing-lockfiles/)).
- `cargo install` ignores the tool's own `Cargo.lock` unless you pass `--locked` ([cargo install](https://doc.rust-lang.org/cargo/commands/cargo-install.html)).
- Building a dependency runs its build script and procedural macros on your machine, so only build code you trust ([Rust blog](https://blog.rust-lang.org/2022/09/14/cargo-cves/)).

**Example of using `cargo-audit`:**

```bash
cargo install cargo-audit --locked
cargo audit
```

For more secure coding guidelines, refer to the [ANSSI Secure Rust Guidelines](https://anssi-fr.github.io/rust-guide/) and the unsafe-code section of the [Rust Language Cheat Sheet](https://cheats.rs/#unsafe-unsound-undefined).

---

## 8. Secure Networking

Rust's memory safety and concurrency features make it well-suited for building secure networked applications.

### 8.1 Secure Communication Protocols

- Don't implement TLS or SSH yourself. Use [rustls](https://github.com/rustls/rustls) 0.23.45 or later for TLS ([RUSTSEC-2026-0285](https://rustsec.org/advisories/RUSTSEC-2026-0285.html)), [russh](https://github.com/Eugeny/russh) 0.60.3 or later for SSH ([RUSTSEC-2026-0154](https://rustsec.org/advisories/RUSTSEC-2026-0154.html)) and [snow](https://github.com/mcginty/snow) 0.9.5 or later for the Noise protocol ([RUSTSEC-2024-0011](https://rustsec.org/advisories/RUSTSEC-2024-0011.html)).
- rustls uses aws-lc-rs by default and prefers the post-quantum hybrid key exchange X25519MLKEM768 ([Cargo.toml](https://github.com/rustls/rustls/blob/v/0.23.45/rustls/Cargo.toml), [provider](https://github.com/rustls/rustls/blob/v/0.23.45/rustls/src/crypto/aws_lc_rs/mod.rs)). `ClientConfig::builder()` panics if no process-wide provider is installed and the crate features don't select exactly one of `aws-lc-rs` and `ring`; keep one, or call `CryptoProvider::install_default()` early in `main`.
- Verify certificates with the operating system's verifier through [rustls-platform-verifier](https://github.com/rustls/rustls-platform-verifier). On Linux it falls back to webpki and doesn't check revocation.
- Don't use the old `webpki` crate (no release since 2023); rustls uses its maintained fork, [rustls-webpki](https://github.com/rustls/webpki).

**Example using `rustls` 0.23 with the platform verifier:**

```rust no_run
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

use rustls::{ClientConfig, ClientConnection, StreamOwned};
use rustls_platform_verifier::ConfigVerifierExt;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // OS certificate verification; protocol versions and cipher suites are rustls's safe defaults.
    let config = Arc::new(ClientConfig::with_platform_verifier()?);

    let server_name = "example.com".try_into()?;
    let conn = ClientConnection::new(config, server_name)?;
    let sock = TcpStream::connect("example.com:443")?;
    let mut tls = StreamOwned::new(conn, sock);

    tls.write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")?;
    let mut response = Vec::new();
    // Cap what you read from the network (here 1 MiB).
    tls.take(1 << 20).read_to_end(&mut response)?;
    println!("Server response: {}", String::from_utf8_lossy(&response));
    Ok(())
}
```

### 8.2 Authentication and Authorization

- Implement robust authentication mechanisms, such as token-based authentication or public-key cryptography.
- Use Rust's type system and libraries to enforce strict access controls and authorization checks.
- Protect against common authentication vulnerabilities, such as weak passwords, session hijacking, and improper session management.

- For JWTs, use jsonwebtoken 10.3.0 or later ([CVE-2026-25537](https://github.com/advisories/GHSA-h395-gr6q-cpjc)) and select exactly one crypto backend feature: with none, `encode` and `decode` compile but panic at run time ([crypto/mod.rs](https://github.com/Keats/jsonwebtoken/blob/v11.1.0/src/crypto/mod.rs)). Prefer `aws_lc_rs`, because `rust_crypto` pulls in `rsa` and its unpatched Marvin advisory.
- Use an HS256 key of at least 256 bits ([RFC 7518 §3.2](https://www.rfc-editor.org/rfc/rfc7518.html#section-3.2)) from secret storage, never a literal in the code.
- Pin the algorithm, and add `iss` and `aud` to the required claims: `set_issuer` and `set_audience` alone still accept tokens that omit them ([validation.rs](https://github.com/Keats/jsonwebtoken/blob/v11.1.0/src/validation.rs)).

```toml
jsonwebtoken = { version = "11.1.0", default-features = false, features = ["aws_lc_rs"] }
```

**Example of a simple JWT-based authentication system:**

```rust
use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode, get_current_timestamp,
};
use serde::{Deserialize, Serialize};

const ISSUER: &str = "https://auth.example.com";
const AUDIENCE: &str = "https://api.example.com";

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    iss: String,
    aud: String,
    exp: u64,
}

fn create_token(user_id: &str, key: &[u8]) -> Result<String, jsonwebtoken::errors::Error> {
    let claims = Claims {
        sub: user_id.to_owned(),
        iss: ISSUER.to_owned(),
        aud: AUDIENCE.to_owned(),
        exp: get_current_timestamp() + 15 * 60,
    };
    encode(&Header::new(Algorithm::HS256), &claims, &EncodingKey::from_secret(key))
}

fn validate_token(token: &str, key: &[u8]) -> Result<Claims, jsonwebtoken::errors::Error> {
    let mut validation = Validation::new(Algorithm::HS256); // pins the algorithm
    validation.set_issuer(&[ISSUER]);
    validation.set_audience(&[AUDIENCE]);
    validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
    Ok(decode::<Claims>(token, &DecodingKey::from_secret(key), &validation)?.claims)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Demo only: a fresh random 256-bit key. In production, load the key
    // from your secret store.
    let mut key = [0u8; 32];
    getrandom::fill(&mut key)?;

    let token = create_token("user123", &key)?; // never log tokens
    let claims = validate_token(&token, &key)?;
    assert_eq!(claims.sub, "user123");
    Ok(())
}
```

### 8.3 Secure Network Programming Practices

- Validate and sanitize network inputs to prevent injection attacks and malformed data.
- Handle network errors and timeouts gracefully to prevent denial-of-service conditions.
- Use secure coding practices, such as input validation, error handling, and secure randomness, in network-related code.

---

## 9. Rust and WebAssembly

Rust's support for WebAssembly (Wasm) enables building secure and performant web applications.

### 9.1 Wasm Security Benefits

- Rust's memory safety guarantees extend to Wasm modules, reducing the risk of memory-related vulnerabilities.
- Wasm's sandbox execution model provides an additional layer of security, isolating untrusted code.
- Rust's types don't prevent cross-site scripting (XSS), which is an output-encoding bug: web-sys's `Element::set_inner_html` is as injectable as JavaScript's `innerHTML` ([web-sys docs](https://docs.rs/web-sys/0.3.106/web_sys/struct.Element.html#method.set_inner_html)). Escape output, sanitize user HTML with [ammonia](https://github.com/rust-ammonia/ammonia) 4.1.4 or later ([RUSTSEC-2026-0213](https://rustsec.org/advisories/RUSTSEC-2026-0213.html)), and deploy a Content Security Policy.
- Rust's buffer-overflow protection covers safe code only. Inside a module's linear memory there are no guard pages between stack, heap and static data and no ASLR, so memory bugs in `unsafe` code or C dependencies meet fewer mitigations ([Lehmann et al., USENIX Security 2020](https://www.usenix.org/system/files/sec20-lehmann.pdf)).

### 9.2 Secure Wasm Development Practices

- Use Rust's built-in Wasm support and libraries to develop secure Wasm modules.
- Follow secure coding practices, such as input validation and error handling, in Wasm code.
- Regularly update Rust and Wasm toolchains to ensure you have the latest security patches.

**Example of a simple Rust to Wasm module:**

```rust
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn add(a: i32, b: i32) -> Option<i32> {
    // The inputs come from JavaScript: return None on overflow instead of wrapping.
    a.checked_add(b)
}

#[wasm_bindgen]
pub fn greet(name: &str) -> String {
    format!("Hello, {}!", name)
}
```

### 9.3 Wasm Interoperability

- Use Rust's FFI capabilities to securely interoperate with JavaScript and other web technologies.
- Validate and sanitize data exchanged between Wasm modules and the host environment.
- Be mindful of potential security risks when integrating Wasm modules with external systems.

---

## 10. Rust and Embedded Systems

Rust's memory safety and low-level control make it suitable for building secure embedded systems and IoT devices.

### 10.1 Embedded Security Challenges

- Embedded systems often have limited resources and strict performance requirements.
- Security vulnerabilities in embedded devices can have severe consequences due to their physical impact.
- Rust's memory safety guarantees and fine-grained control help mitigate common embedded security risks.

### 10.2 Secure Embedded Development Practices

- Use Rust's embedded development frameworks and libraries to build secure and efficient embedded software.
- Follow secure coding practices, such as input validation, error handling, and secure configuration management.
- Implement secure boot, firmware updates, and hardware-based security features when available.

- Guard against stack overflow. With cortex-m-rt's default layout the stack starts at the end of RAM and grows down toward `.bss`, `.data` and the heap, so an overflow silently corrupts statics, even from safe code ([cortex-m-rt docs](https://docs.rs/cortex-m-rt/0.7.7/cortex_m_rt/)). Link with [flip-link](https://github.com/knurling-rs/flip-link), which puts the stack below the statics so an overflow faults instead, or on Armv8-M Mainline enable cortex-m-rt's `set-msplim` feature to set the hardware stack limit.

### 10.3 Rust Embedded Ecosystem

- Leverage Rust's growing embedded ecosystem, including libraries, frameworks, and community resources.
- Participate in embedded Rust working groups and projects to contribute to the development of secure embedded solutions.

---

## 11. Formal Verification

Rust's design and tooling support formal verification techniques for proving program correctness and security properties.

### 11.1 Rust Verification Tools

- Start with [Kani](https://model-checking.github.io/kani/), a bit-precise model checker ([0.68.0](https://github.com/model-checking/kani/releases/tag/kani-0.68.0), released 2026-09-16). It is bounded: loops need a bound that you set with `#[kani::unwind(n)]`, and if the bound is too low the unwinding check fails and the other results are undetermined ([loop unwinding](https://model-checking.github.io/kani/tutorial-loop-unwinding.html)).
- Other verifiers with active development as of 2026-10: [Verus](https://github.com/verus-lang/verus), [Creusot](https://github.com/creusot-rs/creusot), [Aeneas](https://github.com/AeneasVerif/aeneas), [hax](https://github.com/cryspen/hax) and [Flux](https://github.com/flux-rs/flux).
- [Prusti](https://github.com/prusti/prusti) has had no release or default-branch commit since 2024-03-26 and pins nightly-2023-09-15.
- Specify and prove functional correctness, memory safety, and security properties using these tools.
- Integrate formal verification into the development process to catch potential issues early.

To install Kani:

```bash
cargo install --locked kani-verifier
cargo kani setup
```

### 11.2 Verification-Friendly Rust Subsets

- Utilize verification-friendly Rust subsets, such as [Kani's](https://model-checking.github.io/kani/) supported features, to simplify formal reasoning about Rust programs.
- These subsets provide a more tractable foundation for formal verification while retaining Rust's key safety properties.

### 11.3 Verification Challenges and Limitations

- Formal verification can be complex and time-consuming, especially for large codebases.
- Not all Rust features and libraries are amenable to formal verification.
- Combining formal verification with other security practices, such as code review and testing, provides a more comprehensive approach to security assurance.

---

## 12. Case Studies and Real-World Examples

Rust has been successfully used in various security-critical applications and projects.

### 12.1 Firecracker

- [Firecracker](https://github.com/firecracker-microvm/firecracker) is a lightweight virtual machine monitor (VMM) developed by Amazon Web Services using Rust.
- Its isolation comes in layers: KVM plus the VMM boundary, then seccomp filters (on by default), cgroups, namespaces and a jailer that drops privileges ([design doc](https://github.com/firecracker-microvm/firecracker/blob/main/docs/design.md)). Rust is one layer, not the whole boundary: the VMM still had an out-of-bounds write in its virtio-PCI transport, fixed in 1.14.4 and 1.15.1 ([CVE-2026-5747](https://github.com/firecracker-microvm/firecracker/security/advisories/GHSA-776c-mpj7-jm3r)).

### 12.2 Tock Operating System

- [Tock](https://github.com/tock/tock) is a secure embedded operating system for low-power wireless devices and microcontrollers.
- Rust's type and memory safety isolate the kernel from device drivers (capsules); the hardware memory protection unit (MPU) isolates applications from each other and from the kernel ([README](https://github.com/tock/tock/blob/master/README.md)).
- Formally verifying that isolation found seven bugs in Tock's MPU and interrupt code, six of which broke isolation; Rust's type system doesn't prevent such logic errors, missed checks and integer overflows ([TickTock, SOSP '25](https://ranjitjhala.github.io/static/sosp25-ticktock.pdf)).

### 12.3 Zcash

- Zcash is a privacy-focused cryptocurrency that utilizes zero-knowledge proofs for confidential transactions.
- Its original C++ node, zcashd, reached end of support and halted on 2026-07-18 ([end-of-life notice](https://zcash.github.io/zcash/user/end-of-life.html)). Run [Zebra](https://github.com/ZcashFoundation/zebra), the Zcash Foundation's Rust node; the Rust wallet that replaces zcashd's, [Zallet](https://github.com/zcash/zallet), is still in beta.

In each case Rust is one layer of defence, not the whole of it.

---

## 13. Rust Security Community and Initiatives

The Rust community actively contributes to various security initiatives and collaborations.

### 13.1 Rust Secure Code Working Group

- The [Rust Secure Code Working Group](https://github.com/rust-secure-code) works on making it easy to write secure code in Rust ([team page](https://rust-lang.org/governance/teams/#team-wg-secure-code)). Vulnerabilities in Rust itself (the compiler, Cargo, the standard library, crates.io) go to the Rust Security Response WG at security@rust-lang.org ([security policy](https://rust-lang.org/policies/security/)).
- It provides guidance, reviews, and resources to help developers write secure Rust code.

### 13.2 RustSec

- [RustSec](https://rustsec.org/) maintains the RustSec Advisory Database of vulnerabilities in crates.
- It maintains a vulnerability database, provides security alerts, and offers tools like `cargo-audit` for dependency vulnerability scanning.

### 13.3 Community Participation and Collaboration

- Join the Secure Code WG's Zulip stream, `#wg-secure-code`, linked from its [team page](https://rust-lang.org/governance/teams/#team-wg-secure-code), and subscribe to [rustlang-security-announcements](https://groups.google.com/g/rustlang-security-announcements) for security releases of Rust itself.
- Participate in security-related events, workshops, and conferences to share knowledge and collaborate with peers.
- Contribute to open-source Rust security projects, libraries, and tools to help strengthen the ecosystem.

---

## 14. Comparison with Other Languages

Rust's security features and guarantees set it apart from other commonly used languages in security-critical domains.

### 14.1 Rust vs. C/C++

- Safe Rust provides memory safety guarantees, eliminating common vulnerabilities like buffer overflows and use-after-free errors that are prevalent in C/C++. `unsafe` code and C dependencies are outside those guarantees.
- Rust's ownership system and borrow checker enforce strict rules for memory management, reducing the risk of manual memory errors.
- Rust offers safe concurrency primitives, preventing data races and making concurrent programming less error-prone compared to C/C++.

### 14.2 Rust vs. Go

- Go is a memory-safe language too ([CISA/NSA](https://www.cisa.gov/resources-tools/resources/memory-safe-languages-reducing-vulnerabilities-modern-software-development)); its garbage collector prevents use-after-free.
- Go's gap is data races: a race on a multiword value (interface, map, slice or string) can corrupt memory ([Go memory model](https://go.dev/ref/mem)). Safe Rust rejects data races at compile time.
- Both are statically typed, and both check indexes at run time and panic when they are out of range ([Go spec](https://go.dev/ref/spec), [Rust Reference](https://doc.rust-lang.org/reference/expressions/array-expr.html)).
- Rust's fine-grained control over memory layout and allocation allows for more predictable performance and resource usage.

### 14.3 Rust vs. High-Level Languages (e.g., Python, Java)

- Rust offers lower-level control and better performance compared to high-level languages, making it suitable for systems programming and resource-constrained environments.
- Java and Python are memory-safe languages as well ([CISA/NSA](https://www.cisa.gov/resources-tools/resources/memory-safe-languages-reducing-vulnerabilities-modern-software-development)), and Java is statically typed ([JLS §4](https://docs.oracle.com/javase/specs/jls/se25/html/jls-4.html)). Java's data races can't tear references ([JLS §17.7](https://docs.oracle.com/javase/specs/jls/se25/html/jls-17.html)). Rust's distinct guarantee is compile-time data-race freedom in safe code.
- Rust's minimal runtime and lack of garbage collection make it more predictable and deterministic for real-time and embedded systems.

---

## 15. Security Testing in Rust

Comprehensive security testing is crucial for ensuring the robustness of Rust applications.

### 15.1 Fuzz Testing

- Use fuzz testing tools like [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) to automatically generate and test inputs, uncovering potential vulnerabilities.
- Implement fuzz targets for critical parts of your codebase to continuously test for edge cases and unexpected inputs.
- Fuzz your own parsers, not the standard library, and give the fuzzer something to check. Derive `Arbitrary` for a typed input and assert a property such as a round trip: decoding what you encoded gives back the input ([structure-aware fuzzing](https://rust-fuzz.github.io/book/cargo-fuzz/structure-aware-fuzzing.html)).

**Example of a round-trip fuzz target** (marked `ignore` in this repository's tests: it uses your own crate, and `cargo fuzz` builds it with nightly-only flags):

```rust ignore
// fuzz/fuzz_targets/round_trip.rs in a `cargo fuzz init` project.
// `my_parser` is your crate; its `Message` derives `arbitrary::Arbitrary`.
#![no_main]
use libfuzzer_sys::fuzz_target;
use my_parser::{Message, decode, encode};

fuzz_target!(|msg: Message| {
    let bytes = encode(&msg);
    let decoded = decode(&bytes).expect("decode must accept what encode produced");
    assert_eq!(decoded, msg);
});
```

**To set up fuzzing** (running targets needs nightly, [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz)):

```bash
cargo install cargo-fuzz --locked
cargo fuzz init
cargo +nightly fuzz run fuzz_target_1
```

### 15.2 Property-Based Testing

- Utilize property-based testing libraries like [proptest](https://github.com/proptest-rs/proptest) to define properties that your code should satisfy and automatically generate test cases.
- Property-based testing can help uncover edge cases and invariant violations that might be missed by traditional unit tests.

**Example of property-based testing:**

```rust
use proptest::prelude::*;

fn reverse<T: Clone>(v: &[T]) -> Vec<T> {
    v.iter().rev().cloned().collect()
}

fn main() {
    // In a test suite, write this as `proptest! { #[test] fn ... }`.
    proptest!(|(v: Vec<i32>)| {
        let reversed = reverse(&v);
        prop_assert_eq!(v.len(), reversed.len());
        prop_assert_eq!(v, reverse(&reversed));
    });
}
```

### 15.3 Penetration Testing

- Conduct regular penetration testing on Rust applications, especially those exposed to network interfaces or processing untrusted input.
- Use both automated tools and manual testing techniques to identify potential vulnerabilities and misconfigurations.

### 15.4 Continuous Security Testing

- Integrate security testing into your continuous integration and deployment (CI/CD) pipeline.
- Automate security checks, including dependency audits, static analysis, and fuzz testing, to catch potential issues early in the development process.

---

## 16. Secure API Design

Designing secure APIs is crucial for building robust and maintainable Rust applications.

### 16.1 Type-Driven API Design

- Leverage Rust's type system to encode security properties and invariants directly into your API.
- Use newtypes and custom types to prevent common mistakes and ensure correct usage of your API.
- For secrets, a newtype with a hand-written `Debug` that prints `[REDACTED]` only hides the value from logs: the secret stays readable as `.0`, and its memory is freed without being wiped. Moving a value doesn't redact anything.
- Use [`secrecy`](https://docs.rs/secrecy/0.10.3/secrecy/)'s `SecretString` instead: its `Debug` output is redacted, reading it needs an explicit `expose_secret()`, and it zeroizes its memory on drop. Zeroizing is best effort: copies left by moves or earlier reallocation, and the environment variable it came from, remain ([zeroize](https://docs.rs/zeroize/1.9.0/zeroize/)).

**Example of handling a secret:**

```rust
use secrecy::{ExposeSecret, SecretString};

fn main() {
    let api_key = SecretString::from("example-api-key");

    // Debug output is redacted, so the key can't leak through logs by accident.
    assert_eq!(format!("{api_key:?}"), "SecretBox<str>([REDACTED])");

    // Reading the key needs an explicit call that reviewers can grep for.
    assert_eq!(api_key.expose_secret().len(), 15);
} // `api_key` is zeroized here.
```

### 16.2 Error Handling in APIs

- Design clear and informative error types that provide sufficient context without leaking sensitive information.
- Use the [`thiserror`](https://github.com/dtolnay/thiserror) crate for defining custom error types and the [`anyhow`](https://github.com/dtolnay/anyhow) crate for flexible error handling in application code.
- Keep internal details out of client-facing messages. `#[error("... {0}")]` copies the inner error's text, such as file paths, into your message ([thiserror docs](https://docs.rs/thiserror/2.0.21/thiserror/)). Give clients a generic message and keep the inner error as its `source()` for server logs.

**Example of custom error types:**

```rust
use std::error::Error as _;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ApiError {
    #[error("authentication failed")]
    Auth,
    // Generic text for clients; the io::Error stays available as source().
    #[error("internal server error")]
    Internal(#[from] std::io::Error),
}

fn handle(token: &str) -> Result<Vec<u8>, ApiError> {
    if token.is_empty() {
        return Err(ApiError::Auth);
    }
    Ok(std::fs::read("/nonexistent/app/keys.pem")?)
}

fn main() {
    for token in ["", "abc"] {
        if let Err(e) = handle(token) {
            eprintln!("server log: {e}; source: {:?}", e.source()); // full detail
            println!("client sees: {e}"); // no paths or OS errors
        }
    }
}
```

### 16.3 Secure Default Configurations

- Provide secure default configurations for your APIs and libraries.
- Make it easy for users to adopt secure practices and hard to accidentally use insecure options.

---

## 17. Troubleshooting Guide

When working on security-critical Rust applications, developers may encounter common issues. Here's a guide to troubleshooting some of these problems:

### 17.1 Memory Safety Issues

- Use tools like [Miri](https://github.com/rust-lang/miri) to detect undefined behavior and memory safety issues in unsafe code. Miri runs only on nightly, checks only the paths your tests execute, and can't run most FFI calls.
- Leverage the `cargo check` and `cargo clippy` commands to catch potential issues early in the development process.

**Using Miri:**

```bash
rustup +nightly component add miri
cargo +nightly miri test
```

### 17.2 Concurrency Bugs

- Utilize tools like Thread Sanitizer (TSan) to detect data races and other concurrency issues.
- Sanitizers are nightly-only `-Z` flags, and TSan also needs a standard library rebuilt with it (`-Zbuild-std`) ([unstable book](https://doc.rust-lang.org/nightly/unstable-book/compiler-flags/sanitizer.html)). Replace the target with your host triple (`rustc -vV` prints it):

```bash
rustup component add rust-src --toolchain nightly
RUSTFLAGS=-Zsanitizer=thread RUSTDOCFLAGS=-Zsanitizer=thread \
  cargo +nightly test -Zbuild-std --target x86_64-unknown-linux-gnu
```

### 17.3 Cryptographic Misuse

- `cargo audit` only reports dependencies with RustSec advisories. It can't detect misuse such as nonce reuse, comparing MACs with `==` or weak randomness ([cargo-audit README](https://github.com/rustsec/rustsec/blob/main/cargo-audit/README.md)).
- Prevent misuse with APIs that make it hard: compare MAC tags with `Mac::verify_slice`, which runs in constant time, never with `==` ([hmac README](https://github.com/RustCrypto/MACs/blob/master/hmac/README.md)); never repeat an AEAD nonce under the same key ([aead docs](https://docs.rs/aead/0.6.1/aead/type.Nonce.html)); hash passwords with Argon2id ([argon2](https://github.com/RustCrypto/password-hashes/blob/master/argon2/README.md)).
- Before relying on a crate's audit, check what it covered ([5.2](#52-auditing-and-verification)).

### 17.4 Performance Bottlenecks

- Utilize profiling tools like [cargo-flamegraph](https://github.com/flamegraph-rs/flamegraph) to identify performance bottlenecks in your Rust code.
- Consider using the `criterion` crate for micro-benchmarking critical parts of your code.

---

## 18. Emerging Trends in Rust Security

Stay informed about the latest developments in Rust security to leverage new tools and techniques:

### 18.1 Formal Verification Advancements

- Keep an eye on actively developed verifiers such as [Kani](https://model-checking.github.io/kani/), [Verus](https://github.com/verus-lang/verus) and [Creusot](https://github.com/creusot-rs/creusot) ([11.1](#111-rust-verification-tools)).
- Explore emerging tools that combine static and dynamic analysis techniques for more comprehensive security assurance.

### 18.2 Zero-Knowledge Proofs and Privacy-Preserving Computation

- Follow developments in zero-knowledge proof libraries like [ZKCrypto](https://github.com/zkcrypto) and [arkworks](https://github.com/arkworks-rs) for building privacy-preserving applications.
- Explore emerging frameworks for secure multi-party computation (MPC) in Rust.

### 18.3 Post-Quantum Cryptography

- [PQClean](https://github.com/PQClean/PQClean) is archived, and its Rust wrapper `pqcrypto` is unmaintained ([RUSTSEC-2026-0164](https://rustsec.org/advisories/RUSTSEC-2026-0164.html)). Avoid `pqc_kyber` too: it is unmaintained with unpatched advisories ([RUSTSEC-2026-0289](https://rustsec.org/advisories/RUSTSEC-2026-0289.html)).
- For post-quantum key exchange in TLS, rustls's default hybrid X25519MLKEM768 is already on ([8.1](#81-secure-communication-protocols)). For direct use, RustCrypto's [ml-kem](https://github.com/RustCrypto/KEMs/blob/master/ml-kem/README.md) and [ml-dsa](https://github.com/RustCrypto/signatures/blob/master/ml-dsa/README.md) are the replacements RustSec points to; neither has been independently audited.
- Consider the implications of quantum computing on current cryptographic implementations and plan for future migration to post-quantum algorithms.

---

## Conclusion

Rust removes whole classes of memory-safety bugs from safe code. It doesn't remove logic bugs, unsound `unsafe` code, supply-chain risk or misuse of cryptography, so keep reviewing, testing, auditing dependencies and following [Rust's security announcements](https://groups.google.com/g/rustlang-security-announcements).

---

## Glossary

- **Ownership**: Rust's system for managing memory and preventing common memory-related errors.
- **Borrow Checker**: The part of the Rust compiler that enforces the rules of ownership and borrowing.
- **Lifetimes**: A concept in Rust that ensures references are valid for a specific scope.
- **FFI**: Foreign Function Interface, allowing Rust to call functions in other languages and vice versa.
- **WebAssembly (Wasm)**: A binary instruction format for a stack-based virtual machine, which Rust can target.
- **Zero-Knowledge Proof (ZKP)**: A cryptographic method by which one party can prove to another party that they know a value x, without conveying any information apart from the fact that they know the value x.
- **Homomorphic Encryption (HE)**: A form of encryption that allows computations to be performed on encrypted data without decrypting it first.

---

## Additional Resources

- [The Rust Programming Language Book](https://doc.rust-lang.org/book/)
- [ANSSI Secure Rust Guidelines](https://anssi-fr.github.io/rust-guide/)
- [Rust Language Cheat Sheet: unsafe, unsound, undefined](https://cheats.rs/#unsafe-unsound-undefined)
- [RustCrypto](https://github.com/RustCrypto)
- [Rust Cryptography Libraries](https://lib.rs/cryptography)
- [Rust Secure Code Working Group](https://github.com/rust-secure-code)
- [RustSec Advisory Database](https://rustsec.org/)
- [Rust security announcements (mailing list)](https://groups.google.com/g/rustlang-security-announcements)
- [Rust security policy](https://rust-lang.org/policies/security/): report vulnerabilities in Rust itself to security@rust-lang.org
- [Rust Fuzzing Resources](https://github.com/rust-fuzz)
- [Rust Embedded Resources](https://docs.rust-embedded.org/book/)
- **Rust Formal Verification Tools**:
  - [Kani](https://model-checking.github.io/kani/)
  - [Verus](https://github.com/verus-lang/verus)
  - [Creusot](https://github.com/creusot-rs/creusot)
- [Rust Analyzer](https://rust-analyzer.github.io/)

Found advice here that could make code less safe? Report it privately through this repository's [private vulnerability reporting](https://github.com/iAnonymous3000/awesome-rust-security-guide/security/advisories/new). For other errors, open an issue or a pull request.
