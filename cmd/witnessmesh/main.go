package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/requests"

	"witnessmesh/internal/attack"
	"witnessmesh/internal/client"
	"witnessmesh/internal/evidence"
	tlog "witnessmesh/internal/log"
	"witnessmesh/internal/monitor"
	"witnessmesh/internal/policy"
	"witnessmesh/internal/storage"
	"witnessmesh/internal/types"
	"witnessmesh/internal/verifier"
	"witnessmesh/internal/witness"
)

type verifierAdapter struct {
	v          *verifier.Verifier
	witnessMap map[crypto.Hash]string
}

func (a *verifierAdapter) VerifyEquivocation(ctx context.Context, data []byte) (policy.WitnessID, error) {
	res, err := a.v.VerifyBytes(data)
	if err != nil {
		return "", err
	}
	if !res.Valid {
		return "", fmt.Errorf("invalid evidence: %v", res.Errors)
	}
	var eb evidence.EvidenceBundle
	if err := json.Unmarshal(data, &eb); err == nil && len(eb.Cosignatures) > 0 {
		wHash := eb.Cosignatures[0].WitnessID
		if id, ok := a.witnessMap[wHash]; ok {
			return policy.WitnessID(id), nil
		}
		return policy.WitnessID(hex.EncodeToString(wHash[:])), nil
	}
	return "", nil
}

func main() {
	var (
		mode         = flag.String("mode", "demo", "Run mode: demo, log, witness, client, monitor, attack, verify")
		configFile   = flag.String("config", "configs/config.yaml", "Configuration file path")
		dbPath       = flag.String("db", "data/witnessmesh.db", "SQLite database path")
		listenAddr   = flag.String("listen", ":8080", "HTTP listen address")
		witnessName  = flag.String("name", "witness-0", "Witness name for witness mode")
		logURL       = flag.String("log", "http://localhost:8081", "Log URL for witness or client mode")
		evidenceFile = flag.String("evidence", "", "Evidence bundle file to verify (for verify mode)")
		attackName   = flag.String("attack", "", "Attack scenario to run (for attack mode)")
	)
	flag.Parse()
	_ = configFile

	os.MkdirAll("data", 0755)
	os.MkdirAll("configs", 0755)

	store, err := storage.NewSQLiteStore(*dbPath)
	if err != nil {
		log.Fatalf("Failed to initialize storage: %v", err)
	}
	defer store.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

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
		runWitness(ctx, store, *listenAddr, *witnessName, *logURL)
	case "client":
		runClient(ctx, store, *listenAddr, *logURL)
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

	transLog, err := tlog.NewTransparencyLog(store, false)
	if err != nil {
		log.Fatalf("Failed to create transparency log: %v", err)
	}

	// Add initial seed leaves so log has verified tree heads
	for i := 1; i <= 5; i++ {
		msg := crypto.HashBytes([]byte(fmt.Sprintf("initial-block-%d", i)))
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		sig := ed25519.Sign(priv, msg[:])
		var cSig crypto.Signature
		copy(cSig[:], sig)
		transLog.AddLeaf(ctx, requests.Leaf{
			Message:   msg,
			Signature: cSig,
			PublicKey: crypto.PublicKey(pub),
		})
	}
	cp, err := transLog.CreateCheckpoint()
	if err != nil {
		log.Printf("Warning: initial checkpoint creation: %v", err)
	}

	witnesses := make([]*witness.Witness, 3)
	witnessMap := make(map[crypto.Hash]string)
	v := verifier.NewVerifier()
	logPubKey := transLog.PublicKey()
	v.AddTrustedLogKey(&logPubKey)

	for i := 0; i < 3; i++ {
		wName := fmt.Sprintf("witness-%d", i)
		w, err := witness.NewWitnessFromConfig(store, wName, logPubKey)
		if err != nil {
			log.Fatalf("Failed to create witness %d: %v", i, err)
		}
		witnesses[i] = w
		wPub := w.PublicKey()
		v.AddTrustedWitnessKey(&wPub)
		witnessMap[w.KeyHash()] = wName
	}

	// Cosign initial checkpoint if created
	if cp != nil {
		var buf bytes.Buffer
		_ = tlog.WriteCheckpoint(&buf, cp)
		reqBody := fmt.Sprintf("0\n\n%s", buf.String())
		for _, w := range witnesses {
			_, _, _ = w.ProcessCheckpointRequest([]byte(reqBody))
		}
	}

	hostPort := listenAddr
	if strings.HasPrefix(hostPort, ":") {
		hostPort = "127.0.0.1" + hostPort
	}

	var witnessConfigs []client.WitnessConfig
	for _, w := range witnesses {
		witnessConfigs = append(witnessConfigs, client.WitnessConfig{
			Name:      w.Name(),
			PublicKey: w.PublicKey(),
			URL:       fmt.Sprintf("http://%s/witness/%s", hostPort, w.Name()),
			KeyHash:   w.KeyHash(),
		})
	}

	clients := make([]*client.Client, 2)
	for i := 0; i < 2; i++ {
		c, err := client.NewClient(client.ClientConfig{
			LogURL:       fmt.Sprintf("http://%s", hostPort),
			LogPublicKey: logPubKey,
			Witnesses:    witnessConfigs,
			QuorumPolicy: client.QuorumPolicy{
				Type: "kofn",
				K:    2,
			},
			Storage: store,
		})
		if err != nil {
			log.Fatalf("Failed to create client %d: %v", i, err)
		}
		clients[i] = c
	}

	mon, err := monitor.NewMonitor(monitor.MonitorConfig{
		Interval:   10 * time.Second,
		Storage:    store,
		DetectorID: "monitor-0",
	})
	if err != nil {
		log.Fatalf("Failed to create monitor: %v", err)
	}
	for _, w := range witnesses {
		mon.AddWitness(&types.WitnessIdentity{
			Name:      w.Name(),
			PublicKey: w.PublicKey(),
			KeyHash:   w.KeyHash(),
			URL:       w.URL(),
		})
	}

	policyWitnesses := make([]policy.Witness, len(witnesses))
	for i, w := range witnesses {
		wPub := w.PublicKey()
		policyWitnesses[i] = policy.Witness{
			ID:        policy.WitnessID(w.Name()),
			PublicKey: hex.EncodeToString(wPub[:]),
			Endpoint:  w.URL(),
			AddedAt:   time.Now(),
		}
	}
	polConfig := policy.PolicyConfig{
		Version: "1.0",
		Quorum: policy.QuorumPolicy{
			N: 3,
			K: 2,
			F: 0,
		},
		Witnesses: policyWitnesses,
	}
	pol, err := policy.NewPolicyEngine(polConfig, "data/policy.db", &verifierAdapter{v: v, witnessMap: witnessMap})
	if err != nil {
		log.Fatalf("Failed to create policy engine: %v", err)
	}
	defer pol.Close()

	eng := attack.NewEngine(store)

	mux := http.NewServeMux()
	setupAPIRoutes(mux, transLog, witnesses, clients, mon, pol, store, eng)

	for _, w := range witnesses {
		prefix := fmt.Sprintf("/witness/%s", w.Name())
		handler := http.StripPrefix(prefix, w.HTTPHandler())
		mux.Handle(prefix+"/", handler)
		mux.Handle(prefix, handler)
	}

	server := &http.Server{
		Addr:    listenAddr,
		Handler: mux,
	}

	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", listenAddr, err)
	}

	go func() {
		log.Printf("Starting HTTP server on %s", listenAddr)
		if err := server.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Printf("HTTP server error: %v", err)
		}
	}()

	for _, w := range witnesses {
		go w.Run(ctx)
	}
	for _, c := range clients {
		go c.Start(ctx)
	}
	go mon.Start(ctx)

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_, _ = transLog.CreateCheckpoint()
			}
		}
	}()

	<-ctx.Done()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	server.Shutdown(shutdownCtx)
	mon.Stop()
	for _, c := range clients {
		c.Stop()
	}
	log.Println("Demo mode stopped")
}

func runLog(ctx context.Context, store *storage.SQLiteStore, listenAddr string) {
	transLog, err := tlog.NewTransparencyLog(store, false)
	if err != nil {
		log.Fatalf("Failed to create transparency log: %v", err)
	}

	mux := http.NewServeMux()
	setupLogEndpoints(mux, transLog)

	server := &http.Server{Addr: listenAddr, Handler: mux}
	go func() {
		log.Printf("Starting log server on %s", listenAddr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("Log server error: %v", err)
		}
	}()

	<-ctx.Done()
	server.Shutdown(context.Background())
}

func setupLogEndpoints(mux *http.ServeMux, transLog *tlog.TransparencyLog) {
	mux.HandleFunc("/tree-head", func(w http.ResponseWriter, r *http.Request) {
		cp := transLog.GetCheckpoint()
		if cp == nil {
			var err error
			cp, err = transLog.CreateCheckpoint()
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
		w.Header().Set("Content-Type", "text/plain")
		_ = tlog.WriteCheckpoint(w, cp)
	})

	mux.HandleFunc("/add-leaf", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var msg crypto.Hash
		body := make([]byte, 2048)
		n, _ := r.Body.Read(body)
		if n > 0 {
			msg = crypto.HashBytes(body[:n])
		} else {
			msg = crypto.HashBytes([]byte(fmt.Sprintf("entry-%d", time.Now().UnixNano())))
		}
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		sig := ed25519.Sign(priv, msg[:])
		var cSig crypto.Signature
		copy(cSig[:], sig)
		ok, err := transLog.AddLeaf(r.Context(), requests.Leaf{
			Message:   msg,
			Signature: cSig,
			PublicKey: crypto.PublicKey(pub),
		})
		if err != nil || !ok {
			http.Error(w, "Failed to add leaf", http.StatusInternalServerError)
			return
		}
		transLog.CreateCheckpoint()
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok\n"))
	})
}

func runWitness(ctx context.Context, store *storage.SQLiteStore, listenAddr, name, logURL string) {
	log.Printf("Starting standalone witness %s on %s...", name, listenAddr)
	dummyPub, _, _ := ed25519.GenerateKey(rand.Reader)
	w, err := witness.NewWitnessFromConfig(store, name, crypto.PublicKey(dummyPub))
	if err != nil {
		log.Fatalf("Failed to create witness: %v", err)
	}

	server := &http.Server{
		Addr:    listenAddr,
		Handler: w.HTTPHandler(),
	}

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("Witness server error: %v", err)
		}
	}()
	go w.Run(ctx)

	<-ctx.Done()
	server.Shutdown(context.Background())
}

func runClient(ctx context.Context, store *storage.SQLiteStore, listenAddr, logURL string) {
	log.Printf("Starting standalone client connected to %s...", logURL)
	<-ctx.Done()
}

func runMonitor(ctx context.Context, store *storage.SQLiteStore) {
	log.Println("Starting standalone monitor...")
	mon, err := monitor.NewMonitor(monitor.MonitorConfig{
		Interval:   15 * time.Second,
		Storage:    store,
		DetectorID: "monitor-standalone",
	})
	if err != nil {
		log.Fatalf("Failed to create monitor: %v", err)
	}
	go mon.Start(ctx)
	<-ctx.Done()
	mon.Stop()
}

func runAttack(ctx context.Context, store *storage.SQLiteStore, attackName string) {
	if attackName == "" {
		log.Fatal("Attack name required (e.g. -attack split-view-rollback)")
	}

	eng := attack.NewEngine(store)
	if err := eng.RunAttack(ctx, attackName); err != nil {
		log.Fatalf("Attack failed: %v", err)
	}
	log.Println("Attack run completed successfully")
}

func runVerify(evidenceFile string) {
	if evidenceFile == "" {
		log.Fatal("Evidence file required for verify mode (e.g. -evidence data/evidence.json)")
	}

	v := verifier.NewVerifier()
	data, err := os.ReadFile(evidenceFile)
	if err != nil {
		log.Fatalf("Failed to read evidence file: %v", err)
	}

	var eb evidence.EvidenceBundle
	if err := json.Unmarshal(data, &eb); err == nil {
		v.AddTrustedLogKey(&eb.LogIdentity.PublicKey)
	}

	result, err := v.VerifyBytes(data)
	if err != nil {
		log.Fatalf("Verification error: %v", err)
	}

	fmt.Printf("\n=== VERIFICATION RESULT ===\n")
	fmt.Printf("File: %s\n", evidenceFile)
	fmt.Printf("Valid: %v\n", result.Valid)
	fmt.Printf("Case: %v\n", result.Case)
	fmt.Printf("Description: %s\n", result.Description)
	if len(result.Errors) > 0 {
		fmt.Printf("Errors:\n")
		for _, e := range result.Errors {
			fmt.Printf("  - %s\n", e)
		}
	}
	if result.Valid {
		fmt.Println("\nSTATUS: VALID - Cryptographic evidence establishes the stated inconsistency")
	} else {
		fmt.Println("\nSTATUS: INVALID - Evidence is malformed, forged, inconsistent, or insufficient")
		os.Exit(1)
	}
}

func setupAPIRoutes(mux *http.ServeMux, transLog *tlog.TransparencyLog, witnesses []*witness.Witness, clients []*client.Client, mon *monitor.Monitor, pol *policy.PolicyEngine, store *storage.SQLiteStore, eng *attack.Engine) {
	startTime := time.Now()

	mux.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":     "ok",
			"uptime":     time.Since(startTime).String(),
			"nodes":      len(witnesses) + len(clients) + 2, // witnesses + clients + log + monitor
			"maintainer": "Rishi Kulkarni (@geeky-rish)",
			"support":    "chingi11@proton.me",
		})
	})

	mux.HandleFunc("/api/log", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		pk := transLog.PublicKey()
		rh := transLog.RootHash()
		json.NewEncoder(w).Encode(map[string]interface{}{
			"origin":     transLog.Origin(),
			"public_key": hex.EncodeToString(pk[:]),
			"tree_size":  transLog.Size(),
			"root_hash":  hex.EncodeToString(rh[:]),
		})
	})

	mux.HandleFunc("/api/witnesses", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var list []map[string]interface{}
		for _, wt := range witnesses {
			pk := wt.PublicKey()
			kh := wt.KeyHash()
			list = append(list, map[string]interface{}{
				"name":       wt.Name(),
				"public_key": hex.EncodeToString(pk[:]),
				"key_hash":   hex.EncodeToString(kh[:]),
				"url":        wt.URL(),
				"healthy":    true,
			})
		}
		json.NewEncoder(w).Encode(list)
	})

	mux.HandleFunc("/api/checkpoints", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		cp := transLog.GetCheckpoint()
		var list []map[string]interface{}
		if cp != nil {
			list = append(list, map[string]interface{}{
				"origin":    cp.Origin,
				"tree_size": cp.Checkpoint.SignedTreeHead.Size,
				"root_hash": hex.EncodeToString(cp.Checkpoint.SignedTreeHead.RootHash[:]),
				"timestamp": cp.ReceivedAt,
			})
		}
		json.NewEncoder(w).Encode(list)
	})

	mux.HandleFunc("/api/incidents", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		incidents, _ := store.GetIncidents(crypto.Hash{}, 50)
		if incidents == nil {
			incidents = []types.Incident{}
		}
		json.NewEncoder(w).Encode(incidents)
	})

	mux.HandleFunc("/api/evidence", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var bundles []interface{}
		if data, err := os.ReadFile("data/evidence.json"); err == nil {
			var b interface{}
			if json.Unmarshal(data, &b) == nil {
				bundles = append(bundles, b)
			}
		}
		json.NewEncoder(w).Encode(bundles)
	})

	mux.HandleFunc("/api/policy", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"quorum": pol.GetQuorumPolicy(),
			"all":    pol.GetAllWitnesses(),
			"active": pol.GetWitnesses(),
		})
	})

	mux.HandleFunc("/api/scenarios", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		scenarios := eng.GetScenarios()
		var names []map[string]string
		for _, s := range scenarios {
			names = append(names, map[string]string{
				"name":        s.Name,
				"description": s.Description,
				"expected":    s.Expected,
			})
		}
		json.NewEncoder(w).Encode(names)
	})

	mux.HandleFunc("/api/attack", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Scenario string `json:"scenario"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Scenario == "" {
			req.Scenario = "split-view-rollback"
		}
		err := eng.RunAttack(r.Context(), req.Scenario)
		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]interface{}{"status": "error", "error": err.Error()})
			return
		}
		results := eng.GetResults()
		var latest *attack.AttackResult
		if len(results) > 0 {
			latest = results[len(results)-1]
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "success",
			"result": latest,
		})
	})

	// Log HTTP routes on dashboard server
	setupLogEndpoints(mux, transLog)

	// SPA static file handler with index.html fallback
	fs := http.FileServer(http.Dir("web/dist"))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			http.NotFound(w, r)
			return
		}
		path := filepath.Join("web/dist", filepath.Clean(r.URL.Path))
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			fs.ServeHTTP(w, r)
			return
		}
		http.ServeFile(w, r, "web/dist/index.html")
	})
}
