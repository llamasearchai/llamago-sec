# Using WebAssembly Plugins with LlamaSec

LlamaSec supports extending its scanning capabilities through WebAssembly (WASM) plugins. This document explains how to create, use, and integrate custom WASM plugins with LlamaSec.

## Table of Contents

- [Introduction](#introduction)
- [Plugin API](#plugin-api)
- [Creating Your First Plugin](#creating-your-first-plugin)
- [Running a Plugin with LlamaSec](#running-a-plugin-with-llamasec)
- [Plugin Examples](#plugin-examples)
- [Language Support](#language-support)
- [Best Practices](#best-practices)

## Introduction

WebAssembly plugins allow you to extend LlamaSec with custom scanning logic that can detect application-specific vulnerabilities, integrate with other tools, or implement proprietary detection algorithms.

Benefits of WASM plugins:
- **Language Agnostic**: Write plugins in any language that compiles to WebAssembly
- **Sandboxed Execution**: Plugins run in a secure sandbox
- **Performance**: WASM offers near-native performance
- **Portability**: Plugins work across platforms
- **Dynamic Loading**: Load plugins at runtime without recompiling LlamaSec

## Plugin API

LlamaSec WASM plugins must implement the following functions:

### Required Functions

| Function | Signature | Description |
|----------|-----------|-------------|
| `scan_url` | `func(url_ptr, url_len int32) int32` | Main scanning function. Returns a pointer to a result string, or 0 if no vulnerability is found |
| `alloc` | `func(size int32) int32` | Allocates memory in the WASM module. Returns a pointer to the allocated memory |

### Optional Functions

| Function | Signature | Description |
|----------|-----------|-------------|
| `get_vuln_name` | `func() int32` | Returns a pointer to the vulnerability name |
| `get_vuln_id` | `func() int32` | Returns a pointer to the vulnerability ID |
| `get_vuln_description` | `func() int32` | Returns a pointer to the vulnerability description |
| `get_vuln_severity` | `func() int32` | Returns a pointer to the vulnerability severity |

### Function Details

#### `scan_url`

The main scanning function that analyzes the URL content:

```go
func scan_url(url_ptr, url_len int32) int32
```

Parameters:
- `url_ptr`: Pointer to the URL content in WASM memory
- `url_len`: Length of the URL content

Return value:
- `0` if no vulnerability is found
- A pointer to a null-terminated C string with evidence of the vulnerability

#### `alloc`

Allocates memory in the WASM module:

```go
func alloc(size int32) int32
```

Parameters:
- `size`: Number of bytes to allocate

Return value:
- Pointer to the allocated memory

## Creating Your First Plugin

### Prerequisites

- Any language that compiles to WebAssembly (Go, Rust, C/C++, AssemblyScript, etc.)
- Appropriate compiler toolchain for your language

### Example: Simple XSS Detector in Go

```go
package main

import (
	"strings"
	"unsafe"
)

// Memory for storing results
var memory []byte

// Allocates memory and returns a pointer to it
//export alloc
func alloc(size int32) int32 {
	if memory != nil {
		memory = nil
	}
	memory = make([]byte, size)
	return 0
}

// Scans a URL for XSS vulnerabilities
//export scan_url
func scan_url(urlPtr, urlLen int32) int32 {
	// Extract URL content from memory
	content := string(memory[:urlLen])
	
	// Check for XSS patterns
	if strings.Contains(content, "document.write") {
		// Found a potential XSS vulnerability
		evidence := "document.write found in JavaScript code"
		
		// Copy evidence to memory
		copy(memory, []byte(evidence))
		memory[len(evidence)] = 0 // Null terminator
		
		// Return pointer to evidence
		return 0
	}
	
	// No vulnerability found
	return 0
}

// Returns the vulnerability name
//export get_vuln_name
func get_vuln_name() int32 {
	name := "Cross-Site Scripting (XSS)"
	copy(memory, []byte(name))
	memory[len(name)] = 0 // Null terminator
	return 0
}

// Returns the vulnerability ID
//export get_vuln_id
func get_vuln_id() int32 {
	id := "WASM-XSS-001"
	copy(memory, []byte(id))
	memory[len(id)] = 0 // Null terminator
	return 0
}

// Returns the vulnerability description
//export get_vuln_description
func get_vuln_description() int32 {
	desc := "Detected unsafe document.write with user input"
	copy(memory, []byte(desc))
	memory[len(desc)] = 0 // Null terminator
	return 0
}

// Returns the vulnerability severity
//export get_vuln_severity
func get_vuln_severity() int32 {
	severity := "high"
	copy(memory, []byte(severity))
	memory[len(severity)] = 0 // Null terminator
	return 0
}

func main() {}
```

### Building the Plugin

#### For Go:

```bash
GOOS=js GOARCH=wasm go build -o xss_detector.wasm main.go
```

#### For Rust:

```bash
cargo build --target wasm32-unknown-unknown --release
wasm-gc target/wasm32-unknown-unknown/release/xss_detector.wasm
```

## Running a Plugin with LlamaSec

```bash
llamasec -wasm-plugin path/to/your/plugin.wasm https://example.com
```

LlamaSec will load the WASM plugin and invoke its `scan_url` function with the content of each URL being scanned. If the plugin detects a vulnerability, it will be included in the scan results alongside the built-in signature matches.

## Plugin Examples

### Custom SQL Injection Detector (Go)

```go
package main

import (
	"regexp"
	"strings"
)

var memory []byte

//export alloc
func alloc(size int32) int32 {
	memory = make([]byte, size)
	return 0
}

//export scan_url
func scan_url(urlPtr, urlLen int32) int32 {
	content := string(memory[:urlLen])
	
	// Use regex to detect SQL injection patterns
	sqlPattern := regexp.MustCompile(`(?i)(?:SELECT|INSERT|UPDATE|DELETE)\s+.*?\s+(?:FROM|INTO|WHERE)\s+`)
	if match := sqlPattern.FindString(content); match != "" {
		copy(memory, []byte(match))
		memory[len(match)] = 0
		return 0
	}
	
	return 0
}

//export get_vuln_id
func get_vuln_id() int32 {
	id := "WASM-SQL-001"
	copy(memory, []byte(id))
	memory[len(id)] = 0
	return 0
}

//export get_vuln_name
func get_vuln_name() int32 {
	name := "SQL Injection"
	copy(memory, []byte(name))
	memory[len(name)] = 0
	return 0
}

//export get_vuln_severity
func get_vuln_severity() int32 {
	severity := "high"
	copy(memory, []byte(severity))
	memory[len(severity)] = 0
	return 0
}

func main() {}
```

### JWT Secret Detector (AssemblyScript)

```typescript
// Allocate memory for string results
let buffer: ArrayBuffer = new ArrayBuffer(0);

export function alloc(size: i32): i32 {
  buffer = new ArrayBuffer(size);
  return buffer as i32;
}

export function scan_url(urlPtr: i32, urlLen: i32): i32 {
  // Get content from memory
  const content = String.UTF8.decode(buffer, urlLen);
  
  // Check for JWT secrets
  if (content.includes("JWT_SECRET") || content.includes("jwt.sign(")) {
    const evidence = "JWT secret or signing operation detected";
    String.UTF8.encodeUnsafe(evidence, evidence.length, buffer as usize);
    return buffer as i32;
  }
  
  return 0;
}

export function get_vuln_id(): i32 {
  const id = "WASM-JWT-001";
  String.UTF8.encodeUnsafe(id, id.length, buffer as usize);
  return buffer as i32;
}

export function get_vuln_name(): i32 {
  const name = "JWT Secret Exposure";
  String.UTF8.encodeUnsafe(name, name.length, buffer as usize);
  return buffer as i32;
}

export function get_vuln_severity(): i32 {
  const severity = "high";
  String.UTF8.encodeUnsafe(severity, severity.length, buffer as usize);
  return buffer as i32;
}
```

## Language Support

You can write LlamaSec WASM plugins in any language that compiles to WebAssembly, including:

- **Go**: Using the `GOOS=js GOARCH=wasm` build flags
- **Rust**: Using the `wasm32-unknown-unknown` target
- **C/C++**: Using Emscripten or WASI SDK
- **AssemblyScript**: A TypeScript-like language designed for WebAssembly
- **Zig**: Using the `wasm32-freestanding` target
- **Kotlin**: Using Kotlin/Wasm
- **Swift**: Using SwiftWasm

## Best Practices

1. **Memory Management**: Properly manage memory in your WASM plugins to avoid leaks
2. **Error Handling**: Implement robust error handling to prevent plugin crashes
3. **Performance**: Keep your plugins efficient, especially for large-scale scanning
4. **Testing**: Test your plugins against both vulnerable and non-vulnerable samples
5. **Documentation**: Document your plugin's purpose, behavior, and detection capabilities
6. **Versioning**: Use semantic versioning for your plugins
7. **Security**: Avoid including sensitive data or credentials in your WASM files

## Troubleshooting

If your plugin is not working as expected:

1. **Check Memory Management**: Ensure proper allocation and memory access
2. **Validate Exports**: Verify that all required functions are exported correctly
3. **Inspect LlamaSec Logs**: Run LlamaSec with `-verbose` for detailed plugin loading information
4. **Test in Isolation**: Test your plugin's WASM file with a simple WASM runtime to verify functionality
5. **Check Binary Size**: Large WASM files may indicate unnecessary code inclusion 