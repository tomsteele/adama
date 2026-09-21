// work exposes durable task outcomes and the manual tool-resume operation.
package main

import (
	"context"
	"fmt"
	"os"
	"time"

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
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	b, err := sdk.Connect(ctx, sdk.NATSURL())
	if err != nil {
		return err
	}
	defer b.Close()
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
		return fmt.Errorf("usage: work [tasks|tools|resume TOOL]")
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
