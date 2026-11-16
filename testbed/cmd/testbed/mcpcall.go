package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// mcpcall calls one tool of an MCP server over stdio and prints its text
// answer, for gate scripts:
//
//	testbed mcpcall -cmd "bin/jsharvest mcp -o out" -tool endpoints -args '{"status":"static"}'
func mcpcall(args []string) error {
	fset := flag.NewFlagSet("mcpcall", flag.ExitOnError)
	cmdline := fset.String("cmd", "", "the server's command line")
	tool := fset.String("tool", "", "tool name")
	argJSON := fset.String("args", "{}", "the tool's arguments, as JSON")
	fset.Parse(args)
	var a map[string]any
	if err := json.Unmarshal([]byte(*argJSON), &a); err != nil {
		return fmt.Errorf("-args: %w", err)
	}
	cmd := exec.Command("sh", "-c", "exec "+*cmdline)
	cmd.Stderr = os.Stderr
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "testbed-mcpcall"}, nil).Connect(ctx, &mcp.CommandTransport{Command: cmd}, nil)
	if err != nil {
		return err
	}
	defer cs.Close()
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: *tool, Arguments: a})
	if err != nil {
		return err
	}
	for _, c := range res.Content {
		if t, ok := c.(*mcp.TextContent); ok {
			fmt.Println(t.Text)
		}
	}
	if res.IsError {
		return fmt.Errorf("%s: tool error", *tool)
	}
	return nil
}
