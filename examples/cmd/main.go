// Package main provides examples of using LlamaSec
package main

import (
	"fmt"
	"os"

	"github.com/fatih/color"
	"github.com/yourusername/llamasec/examples"
)

func main() {
	// Print header
	printHeader()

	// Check if an example was specified
	if len(os.Args) < 2 {
		printUsage()
		return
	}

	// Run the specified example
	exampleName := os.Args[1]
	switch exampleName {
	case "module":
		fmt.Println(color.GreenString("Running 'Use as Module' example..."))
		examples.UseAsModule()
	case "complete":
		fmt.Println(color.GreenString("Running 'Complete LlamaSec' example..."))
		examples.CompleteLlamaSec()
	case "testing":
		fmt.Println(color.GreenString("Running 'Testing' example..."))
		examples.TestingExample()
	default:
		fmt.Println(color.RedString("Unknown example: %s", exampleName))
		printUsage()
	}
}

// printHeader prints the LlamaSec examples header
func printHeader() {
	fmt.Println("")
	color.New(color.FgGreen, color.Bold).Println("    /\\__/\\    🦙 LlamaSec Examples 🦙")
	color.New(color.FgGreen).Println("   ( o.o  )   Concurrent URL Vulnerability Scanner")
	color.New(color.FgGreen).Println("   > ^ <     Example Runner")
	fmt.Println("")
}

// printUsage prints usage information
func printUsage() {
	fmt.Println("Usage: go run examples/cmd/main.go [example-name]")
	fmt.Println("")
	fmt.Println("Available examples:")
	fmt.Printf("  %s - Demonstrates using LlamaSec as a Go module\n", color.CyanString("module"))
	fmt.Printf("  %s - Shows a complete LlamaSec program with all features\n", color.CyanString("complete"))
	fmt.Printf("  %s - Shows how to test LlamaSec components\n", color.CyanString("testing"))
	fmt.Println("")
	fmt.Println("Example:")
	fmt.Println("  go run examples/cmd/main.go complete")
}
