// Package main implements the supplyscan-mcp entry point.
package main

import (
	"flag"
	"log"

	"github.com/seanhalberthal/supplyscan-mcp/internal/cli"
	"github.com/seanhalberthal/supplyscan-mcp/internal/scanner"
	"github.com/seanhalberthal/supplyscan-mcp/internal/server"
)

func main() {
	cliMode := flag.Bool("cli", false, "Run in CLI mode instead of MCP server")
	flag.Parse()

	scan, err := scanner.New()
	if err != nil {
		log.Fatalf("Failed to initialise scanner: %v", err)
	}

	if *cliMode {
		cli.Run(scan, flag.Args())
		return
	}

	server.Run(scan)
}
