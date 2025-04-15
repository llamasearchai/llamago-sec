package wasm

import (
	"fmt"
	"os"

	"github.com/wasmerio/wasmer-go/wasmer"
)

// PluginResult represents the result from a WASM plugin scan
type PluginResult struct {
	HasVulnerability bool
	ID               string
	Name             string
	Description      string
	Severity         string
	Evidence         string
}

// Plugin represents a WebAssembly plugin for custom scan logic
type Plugin struct {
	Instance *wasmer.Instance
	Memory   *wasmer.Memory
}

// LoadPlugin creates a new WebAssembly plugin from a file
func LoadPlugin(path string) (*Plugin, error) {
	return NewPlugin(path)
}

// NewPlugin creates a new WebAssembly plugin from a file
func NewPlugin(path string) (*Plugin, error) {
	// Read WebAssembly file
	wasmBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("error reading WebAssembly file: %v", err)
	}

	// Create a new WebAssembly Store
	store := wasmer.NewStore(wasmer.NewEngine())

	// Compile the WebAssembly module
	module, err := wasmer.NewModule(store, wasmBytes)
	if err != nil {
		return nil, fmt.Errorf("error compiling WebAssembly module: %v", err)
	}

	// Create import object
	importObject := wasmer.NewImportObject()

	// Create instance of the WebAssembly module
	instance, err := wasmer.NewInstance(module, importObject)
	if err != nil {
		return nil, fmt.Errorf("error instantiating WebAssembly module: %v", err)
	}

	// Get memory
	memory, err := instance.Exports.GetMemory("memory")
	if err != nil {
		return nil, fmt.Errorf("error getting WebAssembly memory: %v", err)
	}

	return &Plugin{
		Instance: instance,
		Memory:   memory,
	}, nil
}

// ScanURL calls the scan_url function in the WebAssembly module
func (p *Plugin) ScanURL(url string) (PluginResult, error) {
	result := PluginResult{
		HasVulnerability: false,
		ID:               "001",
		Name:             "Unknown",
		Description:      "Vulnerability detected by WebAssembly plugin",
		Severity:         "medium",
		Evidence:         "",
	}

	// Get the scan_url function
	scanFunc, err := p.Instance.Exports.GetFunction("scan_url")
	if err != nil {
		return result, fmt.Errorf("error getting scan_url function: %v", err)
	}

	// Write URL to memory
	urlPtr, err := p.writeString(url)
	if err != nil {
		return result, fmt.Errorf("error writing URL to memory: %v", err)
	}

	// Call the function
	scanResult, err := scanFunc(urlPtr, len(url))
	if err != nil {
		return result, fmt.Errorf("error calling scan_url function: %v", err)
	}

	// Check the result (assumes scan_url returns a pointer to a C string)
	resultPtr := scanResult.(int32)
	if resultPtr == 0 {
		return result, nil
	}

	// Read the result string
	resultStr, err := p.readString(resultPtr)
	if err != nil {
		return result, fmt.Errorf("error reading result string: %v", err)
	}

	// If we got a result, set HasVulnerability to true and set the evidence
	result.HasVulnerability = true
	result.Evidence = resultStr

	// Try to get additional info from WASM module if available
	if nameFunc, err := p.Instance.Exports.GetFunction("get_vuln_name"); err == nil {
		if namePtr, err := nameFunc(); err == nil && namePtr.(int32) != 0 {
			if name, err := p.readString(namePtr.(int32)); err == nil {
				result.Name = name
			}
		}
	}

	if idFunc, err := p.Instance.Exports.GetFunction("get_vuln_id"); err == nil {
		if idPtr, err := idFunc(); err == nil && idPtr.(int32) != 0 {
			if id, err := p.readString(idPtr.(int32)); err == nil {
				result.ID = id
			}
		}
	}

	if descFunc, err := p.Instance.Exports.GetFunction("get_vuln_description"); err == nil {
		if descPtr, err := descFunc(); err == nil && descPtr.(int32) != 0 {
			if desc, err := p.readString(descPtr.(int32)); err == nil {
				result.Description = desc
			}
		}
	}

	if sevFunc, err := p.Instance.Exports.GetFunction("get_vuln_severity"); err == nil {
		if sevPtr, err := sevFunc(); err == nil && sevPtr.(int32) != 0 {
			if sev, err := p.readString(sevPtr.(int32)); err == nil {
				result.Severity = sev
			}
		}
	}

	return result, nil
}

// writeString writes a string to WebAssembly memory and returns a pointer to it
func (p *Plugin) writeString(s string) (int32, error) {
	// Allocate memory for the string
	allocFunc, err := p.Instance.Exports.GetFunction("alloc")
	if err != nil {
		return 0, fmt.Errorf("error getting alloc function: %v", err)
	}

	// Call alloc with string length + 1 for null terminator
	ptr, err := allocFunc(len(s) + 1)
	if err != nil {
		return 0, fmt.Errorf("error allocating memory: %v", err)
	}

	// Write string to memory
	offset := ptr.(int32)
	bytes := []byte(s)
	for i := 0; i < len(bytes); i++ {
		p.Memory.Data()[offset+int32(i)] = bytes[i]
	}

	// Add null terminator
	p.Memory.Data()[offset+int32(len(bytes))] = 0

	return offset, nil
}

// readString reads a null-terminated string from WebAssembly memory
func (p *Plugin) readString(ptr int32) (string, error) {
	// Check if pointer is valid
	if ptr < 0 || ptr >= int32(len(p.Memory.Data())) {
		return "", fmt.Errorf("invalid memory pointer: %d", ptr)
	}

	// Read until null terminator
	var bytes []byte
	for i := ptr; i < int32(len(p.Memory.Data())); i++ {
		if p.Memory.Data()[i] == 0 {
			break
		}
		bytes = append(bytes, p.Memory.Data()[i])
	}

	return string(bytes), nil
}

// Close releases the WebAssembly instance resources
func (p *Plugin) Close() {
	if p.Instance != nil {
		p.Instance.Close()
	}
}
