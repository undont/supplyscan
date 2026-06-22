// Package main implements the supplyscan entry point.
package main

import (
	"flag"
	"log"

	"github.com/undont/supplyscan/internal/cli"
	"github.com/undont/supplyscan/internal/scanner"
	"github.com/undont/supplyscan/internal/server"
)

func main() {
	mcpMode := flag.Bool("mcp", false, "Run as MCP server")
	flag.Parse()

	scan, err := scanner.New()
	if err != nil {
		log.Fatalf("Failed to initialise scanner: %v", err)
	}

	if *mcpMode {
		server.Run(scan)
		return
	}

	cli.Run(scan, flag.Args())
}
