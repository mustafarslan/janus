package main

import (
	"errors"
	"flag"
	"fmt"
	"strings"

	"github.com/mustafarslan/janus/pkg/evidence"
)

// Comparing two directories that claim to be the same log.
//
// This is the tool for the morning after a failover went wrong. Nothing prevents
// two writers — the writer lock is per-filesystem, so a promoted
// replica and a partitioned-but-alive primary each hold a valid one — and each
// goes on writing a history that verifies perfectly on its own. `janus-verify`
// cannot see that, and never could: reading one directory, it has nothing to
// compare against.
//
// What this prints is where they stopped agreeing and who recorded a promotion.
// What it does not print is which one is right, because that is not a technical
// question: both are valid logs, and choosing between them depends on which
// effects were released and which clients were answered.
func compare(args []string) error {
	fs := flag.NewFlagSet("compare", flag.ContinueOnError)
	left := fs.String("a", "", "the first evidence directory")
	right := fs.String("b", "", "the second evidence directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *left == "" || *right == "" {
		return errors.New("-a and -b are both required: a fork is a disagreement " +
			"between two directories, and one directory cannot show you one")
	}

	fork, err := evidence.CompareLogs(*left, *right)
	if err != nil {
		return err
	}
	fmt.Println(strings.TrimRight(fork.Describe(*left, *right), "\n"))

	// Exit non-zero on a real divergence, so this can be a step in a runbook and
	// not only something to read. A copy that is merely behind is not a
	// divergence and exits zero: every follower and every backup is behind, and
	// a tool that called that a fork would be one nobody believed.
	if fork.Diverged() {
		return fmt.Errorf("these two directories are not the same log after sequence %d",
			fork.CommonSeq)
	}
	return nil
}
