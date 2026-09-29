// Command janus-signer holds a writer key so the process writing the evidence
// log does not have to.
//
// It answers two questions on a unix socket — which key is this, and sign these
// bytes — and there is no third. See pkg/evidence/keys/remote for what that
// buys and, just as importantly, what it does not: a daemon on the same host as
// the appender is not an HSM, and running it as one would be a control that
// reads as present and is hollow.
//
// The deployment shape it is built for:
//
//	# once, as the key's owner
//	janus-keys gen /var/lib/janus/writer.key
//	chmod 0600 /var/lib/janus/writer.key
//
//	# as a user that is not the one janus-orchd runs as
//	janus-signer -key /var/lib/janus/writer.key -socket /run/janus/signer.sock
//
//	# and the daemon that writes the log
//	janus-orchd -dir /var/lib/janus/evidence -signer /run/janus/signer.sock
//
// The separate uid is the point. With it, a compromise of janus-orchd short of
// root reaches the socket and can ask for signatures while it lasts, but cannot
// read the key and cannot forge anything after it is evicted. Run both as the
// same user and the arrangement is a moving of files, not a boundary.
package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/evidence/keys/remote"
)

var version = "dev"

const usage = `janus-signer %s — writer key custody outside the writing process

usage:
  janus-signer -key <key-file> -socket <path>

flags:
`

func main() {
	var (
		keyPath = flag.String("key", "", "Ed25519 writer key to serve (created if absent)")
		socket  = flag.String("socket", "", "unix socket to listen on")
		mode    = flag.Uint("socket-mode", 0o660,
			"permissions on the socket. The default lets a group reach it and nobody else; "+
				"widen it and every local user can ask this key for signatures.")
		showVer = flag.Bool("version", false, "print version and exit")
	)
	flag.Usage = func() {
		_, _ = fmt.Fprintf(flag.CommandLine.Output(), usage, version)
		flag.PrintDefaults()
	}
	flag.Parse()

	if *showVer {
		fmt.Printf("janus-signer %s\n", version)
		return
	}
	if *keyPath == "" || *socket == "" {
		flag.Usage()
		os.Exit(2)
	}

	if err := run(*keyPath, *socket, os.FileMode(*mode)); err != nil {
		fmt.Fprintf(os.Stderr, "janus-signer: %v\n", err)
		os.Exit(1)
	}
}

func run(keyPath, socket string, mode os.FileMode) error {
	signer, err := keys.LoadOrCreate(keyPath)
	if err != nil {
		return fmt.Errorf("loading the writer key: %w", err)
	}

	// A stale socket from a killed daemon would make every start fail with
	// "address already in use", which reads like a second signer is running
	// when none is. Removing it is safe because a live daemon holds the file
	// open and a second bind would fail anyway — but only for a socket. This
	// deliberately refuses to unlink anything else, so a typo naming the key
	// file does not delete the key.
	if info, err := os.Lstat(socket); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("%s exists and is not a socket; refusing to remove it", socket)
		}
		if err := os.Remove(socket); err != nil {
			return fmt.Errorf("removing the stale socket: %w", err)
		}
	}
	if err := os.MkdirAll(filepath.Dir(socket), 0o750); err != nil {
		return err
	}

	ln, err := net.Listen("unix", socket)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", socket, err)
	}
	defer func() { _ = ln.Close() }()
	// Set after bind: the socket does not exist before it, and the umask would
	// otherwise decide who can reach a signing key.
	if err := os.Chmod(socket, mode); err != nil {
		return fmt.Errorf("setting permissions on %s: %w", socket, err)
	}

	fmt.Printf("janus-signer serving key %s on %s (mode %#o)\n", signer.KeyID(), socket, mode)

	done := make(chan error, 1)
	go func() { done <- remote.Serve(ln, signer) }()

	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)
	select {
	case err := <-done:
		return err
	case <-sigc:
		_ = ln.Close()
		if err := <-done; err != nil && !errors.Is(err, net.ErrClosed) {
			return err
		}
		fmt.Println("janus-signer stopped")
		return nil
	}
}
