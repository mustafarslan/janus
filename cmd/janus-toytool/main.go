// Command janus-toytool is a minimal MCP tool server used to exercise the
// interception spike.
//
// It knows nothing about Janus. That is the point: it is the control in the
// experiment for the claim that an existing tool server is onboarded by a
// configuration change rather than a rewrite.
package main

import (
	"fmt"
	"os"

	"github.com/mustafarslan/janus/pkg/mcp"
)

func main() {
	srv := &mcp.EchoServer{ServerName: "janus-toytool"}
	if err := srv.Serve(os.Stdin, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "janus-toytool: %v\n", err)
		os.Exit(1)
	}
}
