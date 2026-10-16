// Command usage prints this month's usage of every key an API token can
// see, next to each key's name and tier. It only reads, and spends no
// operations.
//
// Usage:
//
//	export RYPT_TOKEN=ry_...
//	go run ./examples/usage [YYYY-MM]
//
// The API token needs the read action.
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"text/tabwriter"

	"github.com/x6c-co/rypt"
)

func main() {
	log.SetFlags(0)
	period := "" // the current month
	if len(os.Args) > 1 {
		period = os.Args[1]
	}
	client, err := rypt.NewClient(os.Getenv("RYPT_TOKEN"), rypt.WithUserAgent("rypt-example-usage"))
	if err != nil {
		log.Fatal(err)
	}
	ctx := context.Background()

	keys, err := client.ListKeys(ctx)
	if err != nil {
		log.Fatal(err)
	}
	byID := make(map[string]rypt.Key, len(keys))
	for _, k := range keys {
		byID[k.ID] = k
	}
	lines, err := client.Usage(ctx, period)
	if err != nil {
		log.Fatal(err)
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "KEY\tTIER\tSTATE\tOPS\tALLOWANCE\tOVERAGE")
	for _, l := range lines {
		name, tier, state := l.KeyID, "", "destroyed"
		if k, ok := byID[l.KeyID]; ok {
			name, tier, state = k.Name, string(k.Tier), string(k.State)
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%d\t%d\n", name, tier, state, l.Ops, l.Allowance, l.OverageOps)
	}
	w.Flush()
}
