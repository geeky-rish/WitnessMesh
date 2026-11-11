package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"witnessmesh/internal/attack"
	"witnessmesh/internal/client"
	"witnessmesh/internal/evidence"
	"witnessmesh/internal/log"
	"witnessmesh/internal/monitor"
	"witnessmesh/internal/policy"
	"witnessmesh/internal/storage"
	"witnessmesh/internal/types"
	"witnessmesh/internal/verifier"
	"witnessmesh/internal/witness"
)

func main() {
	var (
		mode         = flag.String("mode", "demo", "Run mode: demo, log, witness, client, monitor, attack, verify")
		configFile   = flag.String("config", "configs/config.yaml", "Configuration file path")
		dbPath       = flag.String("db", "data/witnessmesh.db", "SQLite database path")
		listenAddr   = flag.String("listen", ":8080", "HTTP listen address")
		evidenceFile = flag.String("evidence", "", "Evidence bundle file to verify (for verify mode)")
		attackName   = flag.String("attack", "", "Attack scenario to run (for attack mode)")
	)
	flag.Parse()

	// Ensure data directory exists
	os.MkdirAll("data", 0755)
	os.MkdirAll("configs", 0755)

	// Initialize storage
	store, err := storage.NewSQLiteStore(*dbPath)
	if err != nil {
		log.Fatalf("Failed to initialize storage: %v", err)
	}
	defer store.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		log.Println("Shutdown signal received")
		cancel()
	}()

	switch *mode {
	case "demo":
		runDemo(ctx, store, *listenAddr)
	case "log":
		runLog(ctx, store, *listenAddr)
	case "witness":
		runWitness(ctx, store, *listenAddr)
	case "client":
		runClient(ctx, store, *listenAddr)
	case "monitor":
		runMonitor(ctx, store)
	case "attack":
		runAttack(ctx, store, *attackName)
	case "verify":
		runVerify(*evidenceFile)
	default:
		log.Fatalf("Unknown mode: %s", *mode)
	}
}

func runDemo(ctx context.Context, store *storage.SQLiteStore, listenAddr string) {
	log.Println("Starting WitnessMesh demo mode...")

	// Create transparency log
	tlog, err := log.NewTransparencyLog(store, false)
	if err != nil {
		log.Fatalf("Failed to create transparency log: %v", err)
	}

	// Create witnesses
	witnesses := make([]*witness.Witness, 3)
	for i := 0; i < 3; i++ {
		w, err := witness.NewWitness(store, fmt.Sprintf("witness-%d", i), tlog.PublicKey())
		if err != nil {
			log.Fatalf("Failed to create witness %d: %v", i, err)
		}
		witnesses[i] = w
	}

	// Create clients
	clients := make([]*client.Client, 2)
	for i := 0; i < 2; i++ {
		c, err := client.NewClient(store, tlog, witnesses)
		if err != nil {
			log.Fatalf("Failed to create client %d: %v", i, err)
		}
		clients[i] = c
	}

	// Create monitor
	mon, err := monitor.NewMonitor(store, tlog, witnesses, clients)
	if err != nil {
		log.Fatalf("Failed to create monitor: %v", err)
	}

	// Create policy engine
	pol, err := policy.NewPolicyEngine(store, witnesses)
	if err != nil {
		log.Fatalf("Failed to create policy engine: %v", err)
	}

	// Start HTTP server for dashboard/API
	mux := http.NewServeMux()
	setupAPIRoutes(mux, tlog, witnesses, clients, mon, pol, store)

	server := &http.Server{
		Addr:    listenAddr,
		Handler: mux,
	}

	go func() {
		log.Printf("Starting HTTP server on %s", listenAddr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("HTTP server error: %v", err)
		}
	}()

	// Start background services
	go tlog.Run(ctx)
	for _, w := range witnesses {
		go w.Run(ctx)
	}
	for _, c := range clients {
		go c.Run(ctx)
	}
	go mon.Run(ctx)

	// Wait for shutdown
	<-ctx.Done()

	// Graceful shutdown
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	server.Shutdown(shutdownCtx)

	log.Println("Demo mode stopped")
}

func runLog(ctx context.Context, store *storage.SQLiteStore, listenAddr string) {
	tlog, err := log.NewTransparencyLog(store, false)
	if err != nil {
		log.Fatalf("Failed to create transparency log: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/tree-head", http.HandlerFunc(tlog.HandleGetTreeHead))
	mux.Handle("/inclusion-proof", http.HandlerFunc(tlog.HandleGetInclusionProof))
	mux.Handle("/consistency-proof", http.HandlerFunc(tlog.HandleGetConsistencyProof))
	mux.Handle("/leaves", http.HandlerFunc(tlog.HandleGetLeaves))
	mux.Handle("/add-leaf", http.HandlerFunc(tlog.HandleAddLeaf))

	server := &http.Server{Addr: listenAddr, Handler: mux}
	go func() {
		log.Printf("Starting log server on %s", listenAddr)
		server.ListenAndServe()
	}()

	go tlog.Run(ctx)
	<-ctx.Done()
	server.Shutdown(context.Background())
}

func runWitness(ctx context.Context, store *storage.SQLiteStore, listenAddr string) {
	// This would need a log public key to verify against
	log.Fatal("Witness mode requires a log public key - use demo mode or provide config")
}

func runClient(ctx context.Context, store *storage.SQLiteStore, listenAddr string) {
	log.Fatal("Client mode not standalone - use demo mode")
}

func runMonitor(ctx context.Context, store *storage.SQLiteStore) {
	log.Fatal("Monitor mode not standalone - use demo mode")
}

func runAttack(ctx context.Context, store *storage.SQLiteStore, attackName string) {
	if attackName == "" {
		log.Fatal("Attack name required")
	}

	eng := attack.NewEngine(store)
	if err := eng.RunAttack(ctx, attackName); err != nil {
		log.Fatalf("Attack failed: %v", err)
	}
	log.Println("Attack completed")
}

func runVerify(evidenceFile string) {
	if evidenceFile == "" {
		log.Fatal("Evidence file required for verify mode")
	}

	v := verifier.NewVerifier()
	result, err := v.VerifyFile(evidenceFile)
	if err != nil {
		log.Fatalf("Verification error: %v", err)
	}

	fmt.Printf("Verification Result: %s\n", result)
	if result.Valid {
		fmt.Println("STATUS: VALID - Cryptographic evidence establishes the stated inconsistency")
	} else {
		fmt.Println("STATUS: INVALID - Evidence is malformed, forged, inconsistent, or insufficient")
		for _, e := range result.Errors {
			fmt.Printf("  Error: %s\n", e)
		}
	}
}

func setupAPIRoutes(mux *http.ServeMux, tlog *log.TransparencyLog, witnesses []*witness.Witness, clients []*client.Client, mon *monitor.Monitor, pol *policy.PolicyEngine, store *storage.SQLiteStore) {
	// API routes for dashboard
	mux.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})

	mux.HandleFunc("/api/log", func(w http.ResponseWriter, r *http.Request) {
		// Return log info
	})

	mux.HandleFunc("/api/witnesses", func(w http.ResponseWriter, r *http.Request) {
		// Return witness statuses
	})

	mux.HandleFunc("/api/checkpoints", func(w http.ResponseWriter, r *http.Request) {
		// Return checkpoint history
	})

	mux.HandleFunc("/api/incidents", func(w http.ResponseWriter, r *http.Request) {
		// Return incidents
	})

	mux.HandleFunc("/api/evidence", func(w http.ResponseWriter, r *http.Request) {
		// Return evidence bundles
	})

	mux.HandleFunc("/api/policy", func(w http.ResponseWriter, r *http.Request) {
		// Return policy config
	})

	mux.HandleFunc("/api/attack", func(w http.ResponseWriter, r *http.Request) {
		// Attack control endpoint
	})

	// Static file serving for dashboard
	mux.Handle("/", http.FileServer(http.Dir("web/dist")))
}