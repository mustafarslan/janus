// Command janus-projection is the operator surface for the Postgres projections.
//
// Every doc comment in `pkg/projection` answers "what if it is wrong?" with
// "rebuild it", and until this existed there was no way to do that without
// writing Go. A control nobody can invoke is a control the deployment does not
// have.
//
//	janus-projection status  -evidence ./janus-evidence -projection postgres://...
//	janus-projection rebuild -evidence ./janus-evidence -projection postgres://...
//
// It reads the log and the projection and nothing else. `rebuild` takes the
// store's writer lock, so it refuses while a daemon is folding — which is
// correct: two things refolding one store is the situation the lock exists to
// prevent, and the refusal says who is holding it.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/mustafarslan/janus/pkg/projection"
)

var version = "dev"

const usage = `janus-projection %s — the Postgres projections, from outside Go

  janus-projection status   -evidence <dir> -projection <dsn>
  janus-projection rebuild  -evidence <dir> -projection <dsn> [-json <path>]

status prints how far behind the log the projection is. The difference comes
first, because that is the number: a tool that makes somebody subtract two
sequences to find it will be misread at three in the morning.

rebuild empties the projection and folds the whole log into it again. It is not
a repair — nothing here is repaired — it is a rederivation from the only thing
that was ever authoritative, which is why it is the answer to every question of
the form "is the projection right?".

flags:
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, usage, version)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]

	var err error
	switch cmd {
	case "status":
		err = status(args)
	case "rebuild":
		err = rebuild(args)
	case "-h", "--help", "help":
		fmt.Fprintf(os.Stderr, usage, version)
		return
	case "-version", "--version":
		fmt.Printf("janus-projection %s\n", version)
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", cmd)
		fmt.Fprintf(os.Stderr, usage, version)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "janus-projection: %v\n", err)
		os.Exit(1)
	}
}

type common struct {
	dir string
	dsn string
}

func bind(fs *flag.FlagSet) *common {
	c := &common{}
	fs.StringVar(&c.dir, "evidence", "./janus-evidence", "evidence segment directory")
	fs.StringVar(&c.dsn, "projection", "", "Postgres connection string for the projection")
	return c
}

func (c *common) check() error {
	if c.dsn == "" {
		return errors.New("-projection is required; there is no default, because a command " +
			"silently pointed at a database nobody meant to use is worse than a failure")
	}
	if _, err := os.Stat(c.dir); err != nil {
		return fmt.Errorf("evidence directory %s: %w", c.dir, err)
	}
	return nil
}

func status(args []string) error {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	c := bind(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := c.check(); err != nil {
		return err
	}
	ctx := context.Background()

	store, err := projection.Open(ctx, c.dsn)
	if err != nil {
		return err
	}
	defer store.Close()

	// The binding is checked before anything is reported, so a status command
	// pointed at another deployment's database says so rather than printing a
	// confident number about the wrong log.
	if err := projection.CheckLogBinding(ctx, store, c.dir); err != nil {
		return err
	}

	projected, builtBy, err := store.Head(ctx)
	if err != nil {
		return err
	}
	head, err := projection.LogHead(c.dir)
	if err != nil {
		return err
	}

	switch {
	case projected > head:
		// Possible only if the projection was folded from a longer log than the
		// one here, which the binding check should have caught — so it is worth
		// saying loudly rather than printing a negative.
		fmt.Printf("AHEAD by %d events — the projection has folded past this log's end\n",
			projected-head)
	case head == projected:
		fmt.Println("caught up")
	default:
		fmt.Printf("behind by %d events\n", head-projected)
	}
	fmt.Printf("  projection  %d\n", projected)
	fmt.Printf("  log         %d\n", head)
	if builtBy != "" {
		fmt.Printf("  derived by  %s\n", builtBy)
	}
	return nil
}

func rebuild(args []string) error {
	fs := flag.NewFlagSet("rebuild", flag.ExitOnError)
	c := bind(fs)
	jsonOut := fs.String("json", "", "also write the timing as JSON to this path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := c.check(); err != nil {
		return err
	}
	ctx := context.Background()

	store, err := projection.Open(ctx, c.dsn)
	if err != nil {
		return err
	}
	defer store.Close()

	p := projection.NewProjector(store, c.dir)
	// Timed from outside the projector, around everything a caller waits for:
	// `FoldPhases` starts at the catch-up, and the truncate, the connection and
	// the writer lock happen before that. An operator restoring a log is
	// waiting for all of it, so the headline is wall time and the phases sit
	// under it.
	t0 := time.Now()
	head, err := p.Rebuild(ctx)
	took := time.Since(t0)
	if err != nil {
		if errors.Is(err, projection.ErrNotTheWriter) {
			return fmt.Errorf("%w\n\nsomething else is folding this projection — a running "+
				"janus-orchd, most likely. Stop it before rebuilding: two things refolding "+
				"one store is what the lock exists to prevent", err)
		}
		return err
	}
	fmt.Printf("rebuilt to sequence %d in %s\n", head, took.Round(time.Millisecond))
	if *jsonOut == "" {
		return nil
	}
	return writeRebuildJSON(*jsonOut, head, took, p.FoldPhases())
}

// writeRebuildJSON reports what the rebuild cost and what it worked on.
//
// `kept` is in it for the same reason the restore drill fails a sweep that
// verified too few events: a rebuild of a log whose records the projector keeps
// none of finishes fast, reports the right head, and has measured a scan. The
// two counts side by side are what tell a fold from a skim.
func writeRebuildJSON(path string, head uint64, took time.Duration, f projection.FoldPhases) error {
	doc := map[string]any{
		"head":    head,
		"took_ns": took.Nanoseconds(),
		"scanned": f.Scanned,
		"kept":    f.Kept,
		"phases": map[string]any{
			"read_ns":   f.Read.Nanoseconds(),
			"apply_ns":  f.Apply.Nanoseconds(),
			"commit_ns": f.Commit.Nanoseconds(),
			// The fold's own total, not the wall time above: the difference
			// between them is the truncate, the pool and the writer lock, which
			// `FoldPhases` never sees.
			"fold_ns":     f.Total.Nanoseconds(),
			"residual_ns": f.Residual().Nanoseconds(),
		},
		"statements": map[string]any{
			"total": f.Statements, "saga": f.StmtSaga, "clear": f.StmtClear,
			"step": f.StmtStep, "touch": f.StmtTouch,
		},
	}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}
