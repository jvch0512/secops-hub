package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/jvch0512/secops-hub/internal/analyst"
	"github.com/jvch0512/secops-hub/internal/hub"
	"github.com/jvch0512/secops-hub/internal/server"
	"github.com/jvch0512/secops-hub/internal/sim"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8080", "listen address (loopback by default; this is a demo, do not expose it)")
	seed := flag.Int64("seed", 42, "simulation seed (same seed, same attack story)")
	every := flag.Duration("every", 700*time.Millisecond, "interval between simulated alerts")
	warm := flag.Int("warmup", 120, "alerts generated before the first page load, so the dashboard is never empty")
	flag.Parse()

	h := hub.New()
	g := sim.New(*seed, time.Now().UTC().Add(-time.Hour))
	for i := 0; i < *warm; i++ {
		h.Add(g.Next())
	}
	var client *analyst.Client
	if key := os.Getenv("ANTHROPIC_API_KEY"); key != "" {
		client = analyst.NewClient(key, os.Getenv("ANALYST_MODEL"))
		log.Printf("AI analyst: Claude (%s). Alert fields (synthetic here) are sent to the Anthropic API.", client.Model)
	} else {
		client = &analyst.Client{}
		log.Print("AI analyst: offline knowledge base (set ANTHROPIC_API_KEY to enable Claude)")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	go func() {
		t := time.NewTicker(*every)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				h.Add(g.Next())
			}
		}
	}()
	srv := &http.Server{Addr: *addr, Handler: (&server.Server{Hub: h, Analyst: client}).Handler(), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		sc, c := context.WithTimeout(context.Background(), 3*time.Second)
		defer c()
		_ = srv.Shutdown(sc)
	}()
	fmt.Printf("SecOps Hub on http://%s\n", *addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
