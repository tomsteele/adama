// work exposes durable task outcomes and the manual tool-resume operation.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"adama/internal/coverage"
	"adama/sdk"
	"github.com/nats-io/nats.go/jetstream"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) > 0 && args[0] == "coverage" {
		return showCoverage(args[1:], os.Stdout)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	b, err := sdk.Connect(ctx, sdk.NATSURL())
	if err != nil {
		return err
	}
	defer b.Close()
	if len(args) == 1 && args[0] == "registered" {
		registrations, err := b.Registrations(ctx)
		if err != nil {
			return err
		}
		for _, registration := range registrations {
			if err := json.NewEncoder(os.Stdout).Encode(registration); err != nil {
				return err
			}
		}
		return nil
	}
	if len(args) > 0 && args[0] == "inventory" {
		if len(args) == 2 && args[1] == "begin" {
			return b.SetInventory(ctx, nil, false)
		}
		if len(args) > 2 && args[1] == "set" {
			return b.SetInventory(ctx, args[2:], true)
		}
		if len(args) == 1 {
			inv, err := b.Inventory(ctx)
			if err != nil {
				return err
			}
			return json.NewEncoder(os.Stdout).Encode(inv)
		}
		return fmt.Errorf("usage: work inventory [begin|set WORKER...]")
	}
	if len(args) == 2 && args[0] == "resume" {
		if err := b.Tools.Delete(ctx, args[1]); err != nil {
			return err
		}
		fmt.Printf("Resumed %s; terminal tasks remain terminal. Use a new scope for an explicit rescan.\n", args[1])
		return nil
	}
	var kv jetstream.KeyValue
	if len(args) == 0 || (len(args) == 1 && args[0] == "tasks") {
		kv = b.KV
	} else if len(args) == 1 && args[0] == "tools" {
		kv = b.Tools
	} else {
		return fmt.Errorf("usage: work [tasks|tools|registered|inventory|resume TOOL|coverage --run RUN|coverage --scope SCOPE]")
	}
	keys, err := kv.ListKeys(ctx)
	if err != nil {
		return err
	}
	defer keys.Stop()
	for key := range keys.Keys() {
		e, err := kv.Get(ctx, key)
		if err != nil {
			return err
		}
		fmt.Println(string(e.Value()))
	}
	return nil
}

func showCoverage(args []string, out io.Writer) error {
	flags := flag.NewFlagSet("coverage", flag.ContinueOnError)
	var filter coverage.Filter
	flags.StringVar(&filter.Run, "run", "", "select the scopes used by this run (includes shared work from other runs)")
	flags.StringVar(&filter.Scope, "scope", "", "select a work scope")
	timeout := flags.Duration("timeout", 5*time.Minute, "maximum snapshot time")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || (filter.Run == "" && filter.Scope == "") || *timeout <= 0 {
		return fmt.Errorf("coverage requires --run or --scope and a positive --timeout")
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	b, err := sdk.Connect(ctx, sdk.NATSURL())
	if err != nil {
		return err
	}
	defer b.Close()
	report, err := coverage.Snapshot(ctx, b, filter)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}
