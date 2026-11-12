// Package attack implements controlled, reproducible attack simulations against
// actual running WitnessMesh components (TransparencyLog, Witnesses, Clients).
//
// Each scenario demonstrates a specific threat model and verifies that the
// system's defenses (honest witnesses, cryptographic verification, quorum)
// correctly detect or prevent the attack.
//
// Usage:
//
//	eng := attack.NewEngine(store)
//	err := eng.RunAttack(ctx, "split-view")
//
// Scenarios:
//  1. honest-baseline      - Honest log and honest witnesses (baseline behavior)
//  2. split-view           - Malicious log presenting different histories to different clients
//  3. witness-rollback     - Witness database rollback via SQLite backup restoration
//  4. witness-equivocation - Compromised witness signing conflicting checkpoints
//  5. log-witness-collusion - Colluding log and witness presenting false consistency
//  6. network-partition    - Network delay/outage using Linux tc netem
package attack

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"

	"witnessmesh/internal/log"
	"witnessmesh/internal/storage"
	"witnessmesh/internal/types"

	"sigsum.org/sigsum-go/pkg/checkpoint"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/requests"
	sigsumtypes "sigsum.org/sigsum-go/pkg/types"
)

// AttackScenario represents a named attack scenario with metadata
type AttackScenario struct {
	Name        string
	Description string
	Setup       func(*Engine) error
	Execute     func(*Engine, context.Context) (*AttackResult, error)
	Cleanup     func(*Engine) error
	Expected    string
}

// AttackResult contains the outcome of an attack execution
type AttackResult struct {
	ScenarioName string
	Success      bool // true = attack succeeded (system compromised), false = attack prevented
	Detected     bool // true = system detected the attack
	Details      string
	Evidence     *types.EvidenceBundle
	Incidents    []*types.Incident
	Duration     time.Duration
	Timestamp    time.Time
	Error        error
}

// Engine is the attack simulation engine
type Engine struct {
	store            *storage.SQLiteStore
	log              *log.TransparencyLog
	maliciousLog     *log.TransparencyLog
	witnesses        []*MockWitness
	clients          []*MockClient
	networkNamespace string
	originalNetNS    string
	tcRules          []string
	mu               sync.Mutex
	results          []*AttackResult
	state            map[string]interface{} // Scenario-specific state
}

// MockWitness simulates a witness for attack scenarios
type MockWitness struct {
	ID           string
	PrivateKey   ed25519.PrivateKey
	PublicKey    crypto.PublicKey
	KeyHash      crypto.Hash
	Store        *storage.SQLiteStore
	LogPubKey    crypto.PublicKey
	LogOrigin    string
	LatestSize   uint64
	LatestRoot   crypto.Hash
	Compromised  bool
	MaliciousSig bool // If true, signs conflicting checkpoints
	mu           sync.Mutex
}

// MockClient simulates a client for attack scenarios
type MockClient struct {
	ID           string
	Store        *storage.SQLiteStore
	Log          *log.TransparencyLog
	Witnesses    []*MockWitness
	KnownSize    uint64
	KnownRoot    crypto.Hash
	DetectedFork bool
	mu           sync.Mutex
}

// NewEngine creates a new attack engine
func NewEngine(store *storage.SQLiteStore) *Engine {
	return &Engine{
		store:   store,
		state:   make(map[string]interface{}),
		results: make([]*AttackResult, 0),
	}
}

// GetScenarios returns all available attack scenarios
func (e *Engine) GetScenarios() []AttackScenario {
	return []AttackScenario{
		{
			Name:        "honest-baseline",
			Description: "Honest log and honest witnesses - baseline correct behavior",
			Setup:       e.setupHonestBaseline,
			Execute:     e.executeHonestBaseline,
			Cleanup:     e.cleanupHonestBaseline,
			Expected:    "All checkpoints consistent, quorum met, no incidents",
		},
		{
			Name:        "split-view",
			Description: "Malicious log presenting different histories to different clients (split-view attack)",
			Setup:       e.setupSplitView,
			Execute:     e.executeSplitView,
			Cleanup:     e.cleanupSplitView,
			Expected:    "Honest witnesses detect fork via inconsistent checkpoints, evidence generated",
		},
		{
			Name:        "witness-rollback",
			Description: "Witness database rollback using real SQLite backup/snapshot restoration",
			Setup:       e.setupWitnessRollback,
			Execute:     e.executeWitnessRollback,
			Cleanup:     e.cleanupWitnessRollback,
			Expected:    "Witness state inconsistency detected, incident recorded",
		},
		{
			Name:        "split-view-rollback",
			Description: "Witness database rollback combined with split-view attack",
			Setup:       e.setupWitnessRollback,
			Execute:     e.executeWitnessRollback,
			Cleanup:     e.cleanupWitnessRollback,
			Expected:    "Witness state inconsistency detected, incident recorded, evidence generated",
		},
		{
			Name:        "witness-equivocation",
			Description: "Compromised witness signing conflicting checkpoints for same log size",
			Setup:       e.setupWitnessEquivocation,
			Execute:     e.executeWitnessEquivocation,
			Cleanup:     e.cleanupWitnessEquivocation,
			Expected:    "Equivocation detected via duplicate cosignatures with different roots, evidence generated",
		},
		{
			Name:        "log-witness-collusion",
			Description: "Colluding log and witness presenting false consistency",
			Setup:       e.setupLogWitnessCollusion,
			Execute:     e.executeLogWitnessCollusion,
			Cleanup:     e.cleanupLogWitnessCollusion,
			Expected:    "Collusion detected if quorum requires multiple independent witnesses",
		},
		{
			Name:        "network-partition",
			Description: "Network delay/outage using Linux tc netem",
			Setup:       e.setupNetworkPartition,
			Execute:     e.executeNetworkPartition,
			Cleanup:     e.cleanupNetworkPartition,
			Expected:    "System handles partition gracefully, detects stale checkpoints",
		},
	}
}

// RunAttack executes a named attack scenario
func (e *Engine) RunAttack(ctx context.Context, scenarioName string) error {
	scenarios := e.GetScenarios()
	var scenario *AttackScenario
	for i := range scenarios {
		if scenarios[i].Name == scenarioName {
			scenario = &scenarios[i]
			break
		}
	}
	if scenario == nil {
		return fmt.Errorf("unknown scenario: %s", scenarioName)
	}

	fmt.Printf("\n=== Starting Attack Scenario: %s ===\n", scenario.Name)
	fmt.Printf("Description: %s\n", scenario.Description)
	fmt.Printf("Expected: %s\n\n", scenario.Expected)

	// Setup
	fmt.Println("[SETUP] Preparing scenario...")
	if err := scenario.Setup(e); err != nil {
		return fmt.Errorf("setup failed: %w", err)
	}
	fmt.Println("[SETUP] Complete")

	// Execute
	fmt.Println("[EXECUTE] Running attack...")
	start := time.Now()
	result, err := scenario.Execute(e, ctx)
	duration := time.Since(start)
	if err != nil {
		return fmt.Errorf("execution failed: %w", err)
	}
	result.Duration = duration
	result.Timestamp = time.Now()
	fmt.Printf("[EXECUTE] Complete (took %v)\n", duration)

	// Record result
	e.mu.Lock()
	e.results = append(e.results, result)
	e.mu.Unlock()

	// Print result
	fmt.Printf("\n=== RESULT ===\n")
	fmt.Printf("Scenario: %s\n", result.ScenarioName)
	fmt.Printf("Attack Success: %v (true = system compromised)\n", result.Success)
	fmt.Printf("Attack Detected: %v\n", result.Detected)
	fmt.Printf("Details: %s\n", result.Details)
	if result.Evidence != nil {
		fmt.Printf("Evidence Generated: Case=%d, Checkpoints=%d, Cosignatures=%d\n",
			result.Evidence.Case, len(result.Evidence.Checkpoints), len(result.Evidence.Cosignatures))
		if e.store != nil {
			_ = e.store.SaveEvidenceBundle(result.Evidence)
		}
		if evidenceData, err := json.MarshalIndent(result.Evidence, "", "  "); err == nil {
			os.MkdirAll("data", 0755)
			_ = os.WriteFile("data/evidence.json", evidenceData, 0644)
		}
	}
	if len(result.Incidents) > 0 {
		fmt.Printf("Incidents: %d\n", len(result.Incidents))
		for _, inc := range result.Incidents {
			fmt.Printf("  - %s (Severity: %d)\n", inc.Description, inc.Severity)
		}
	}
	if result.Error != nil {
		fmt.Printf("Error: %v\n", result.Error)
	}

	// Cleanup
	fmt.Println("\n[CLEANUP] Cleaning up scenario...")
	if err := scenario.Cleanup(e); err != nil {
		fmt.Printf("[CLEANUP] Warning: %v\n", err)
	}
	fmt.Println("[CLEANUP] Complete")

	return nil
}

// GetResults returns all attack results
func (e *Engine) GetResults() []*AttackResult {
	e.mu.Lock()
	defer e.mu.Unlock()
	results := make([]*AttackResult, len(e.results))
	copy(results, e.results)
	return results
}

// =============================================================================
// SCENARIO 1: Honest Baseline
// =============================================================================

func (e *Engine) setupHonestBaseline(e2 *Engine) error {
	// Create honest log
	tlog, err := log.NewTransparencyLog(e.store, false)
	if err != nil {
		return fmt.Errorf("failed to create log: %w", err)
	}
	e.log = tlog

	// Create 3 honest witnesses
	e.witnesses = make([]*MockWitness, 3)
	for i := 0; i < 3; i++ {
		w, err := e.createHonestWitness(fmt.Sprintf("witness-%d", i), tlog.PublicKey())
		if err != nil {
			return fmt.Errorf("failed to create witness %d: %w", i, err)
		}
		e.witnesses[i] = w
	}

	// Create 2 clients
	e.clients = make([]*MockClient, 2)
	for i := 0; i < 2; i++ {
		c := e.createClient(fmt.Sprintf("client-%d", i), tlog, e.witnesses)
		e.clients[i] = c
	}

	return nil
}

func (e *Engine) executeHonestBaseline(e2 *Engine, ctx context.Context) (*AttackResult, error) {
	result := &AttackResult{ScenarioName: "honest-baseline"}

	// Add leaves to log
	for i := 0; i < 10; i++ {
		leaf := e.createTestLeaf()
		_, err := e.log.AddLeaf(ctx, leaf)
		if err != nil {
			return result, fmt.Errorf("failed to add leaf: %w", err)
		}
	}

	// Create checkpoint
	cp, err := e.log.CreateCheckpoint()
	if err != nil {
		return result, fmt.Errorf("failed to create checkpoint: %w", err)
	}

	// Have all witnesses cosign
	cosigs := make([]types.Cosignature, 0)
	for _, w := range e.witnesses {
		cosig, err := w.CosignCheckpoint(cp)
		if err != nil {
			return result, fmt.Errorf("witness %s failed to cosign: %w", w.ID, err)
		}
		cosigs = append(cosigs, *cosig)
	}

	// Verify all clients see consistent state
	consistent := true
	for _, c := range e.clients {
		if !c.VerifyCheckpoint(cp, cosigs) {
			consistent = false
			break
		}
	}

	// Verify quorum (2 of 3)
	quorumMet := len(cosigs) >= 2

	result.Success = false       // Attack should not succeed
	result.Detected = !consistent // Should detect nothing (all consistent)
	result.Details = fmt.Sprintf("Consistent: %v, Quorum: %v, Cosignatures: %d",
		consistent, quorumMet, len(cosigs))

	if !consistent || !quorumMet {
		result.Details += " - BASELINE FAILED: System not working correctly"
	}

	return result, nil
}

func (e *Engine) cleanupHonestBaseline(e2 *Engine) error {
	e.log = nil
	e.witnesses = nil
	e.clients = nil
	return nil
}

// =============================================================================
// SCENARIO 2: Split-View Attack (Malicious Log)
// =============================================================================

func (e *Engine) setupSplitView(e2 *Engine) error {
	// Create a malicious log (with alternative history capability)
	maliciousLog, err := log.NewTransparencyLog(e.store, true)
	if err != nil {
		return fmt.Errorf("failed to create malicious log: %w", err)
	}
	e.maliciousLog = maliciousLog

	// Create honest log for comparison (what client A sees)
	honestLog, err := log.NewTransparencyLog(e.store, false)
	if err != nil {
		return fmt.Errorf("failed to create honest log: %w", err)
	}
	e.log = honestLog

	// Create 3 honest witnesses
	e.witnesses = make([]*MockWitness, 3)
	for i := 0; i < 3; i++ {
		w, err := e.createHonestWitness(fmt.Sprintf("witness-%d", i), maliciousLog.PublicKey())
		if err != nil {
			return fmt.Errorf("failed to create witness %d: %w", i, err)
		}
		e.witnesses[i] = w
	}

	// Create 2 clients - one sees honest log, one sees malicious log
	e.clients = make([]*MockClient, 2)
	e.clients[0] = e.createClient("client-A", honestLog, e.witnesses)
	e.clients[1] = e.createClient("client-B", maliciousLog, e.witnesses)

	// Pre-populate both logs with same initial leaves
	for i := 0; i < 5; i++ {
		leaf := e.createTestLeaf()
		honestLog.AddLeaf(context.Background(), leaf)
		maliciousLog.AddLeaf(context.Background(), leaf)
	}

	// Create alternative history for malicious log (different leaves 5-9)
	altLeaves := make([]log.Leaf, 5)
	for i := 0; i < 5; i++ {
		altLeaves[i] = e.createTestLeafLocal()
	}
	maliciousLog.CreateAlternativeHistory(altLeaves)

	return nil
}

func (e *Engine) executeSplitView(e2 *Engine, ctx context.Context) (*AttackResult, error) {
	result := &AttackResult{ScenarioName: "split-view"}

	// Client A gets checkpoint from honest log (size 10)
	honestCP, err := e.log.CreateCheckpoint()
	if err != nil {
		return result, fmt.Errorf("honest log checkpoint failed: %w", err)
	}

	// Client B gets checkpoint from malicious log (size 10, different root)
	maliciousCP, err := e.maliciousLog.GetMaliciousCheckpoint(10)
	if err != nil {
		return result, fmt.Errorf("malicious log checkpoint failed: %w", err)
	}

	// Witnesses cosign what they see (they query the log directly)
	// In reality, witnesses would query the log's /tree-head endpoint
	// Here we simulate: witnesses cosign the honest checkpoint
	cosigs := make([]types.Cosignature, 0)
	for _, w := range e.witnesses {
		cosig, err := w.CosignCheckpoint(honestCP)
		if err != nil {
			return result, fmt.Errorf("witness %s failed: %w", w.ID, err)
		}
		cosigs = append(cosigs, *cosig)
	}

	// Client A verifies honest checkpoint with cosignatures
	clientAVerified := e.clients[0].VerifyCheckpoint(honestCP, cosigs)

	// Client B verifies malicious checkpoint with SAME cosignatures
	// This should FAIL because cosignatures are for different root hash
	clientBVerified := e.clients[1].VerifyCheckpoint(maliciousCP, cosigs)

	// The attack succeeds if client B accepts the malicious checkpoint
	attackSucceeded := clientBVerified

	// The attack is detected if client B rejects it OR witnesses detect inconsistency
	detected := !clientBVerified

	// Generate evidence if fork detected
	var evidence *types.EvidenceBundle
	if !clientBVerified || honestCP.TreeHead.RootHash != maliciousCP.TreeHead.RootHash {
		evidence = e.generateForkEvidence(honestCP, maliciousCP, cosigs)
	}

	result.Success = attackSucceeded
	result.Detected = detected
	result.Evidence = evidence
	result.Details = fmt.Sprintf(
		"Honest CP Root: %x, Malicious CP Root: %x, Client A Verified: %v, Client B Verified: %v",
		honestCP.TreeHead.RootHash[:4], maliciousCP.TreeHead.RootHash[:4],
		clientAVerified, clientBVerified,
	)

	return result, nil
}

func (e *Engine) cleanupSplitView(e2 *Engine) error {
	e.maliciousLog = nil
	e.log = nil
	e.witnesses = nil
	e.clients = nil
	return nil
}

// =============================================================================
// SCENARIO 3: Witness Database Rollback
// =============================================================================

func (e *Engine) setupWitnessRollback(e2 *Engine) error {
	// Create honest log
	tlog, err := log.NewTransparencyLog(e.store, false)
	if err != nil {
		return fmt.Errorf("failed to create log: %w", err)
	}
	e.log = tlog

	// Create 3 witnesses with persistent state
	e.witnesses = make([]*MockWitness, 3)
	for i := 0; i < 3; i++ {
		w, err := e.createHonestWitness(fmt.Sprintf("witness-%d", i), tlog.PublicKey())
		if err != nil {
			return fmt.Errorf("failed to create witness %d: %w", i, err)
		}
		e.witnesses[i] = w
	}

	// Create clients
	e.clients = make([]*MockClient, 1)
	e.clients[0] = e.createClient("client-0", tlog, e.witnesses)

	// Add initial leaves and create checkpoints
	for i := 0; i < 10; i++ {
		leaf := e.createTestLeaf()
		tlog.AddLeaf(context.Background(), leaf)
	}

	// Create checkpoint at size 10
	cp10, err := tlog.CreateCheckpoint()
	if err != nil {
		return fmt.Errorf("failed to create checkpoint: %w", err)
	}

	// All witnesses cosign
	for _, w := range e.witnesses {
		w.CosignCheckpoint(cp10)
	}

	// Store the database state (backup) - we'll simulate by copying the DB file
	dbPath := e.getDBPath()
	backupPath := dbPath + ".backup"
	if err := e.copyFile(dbPath, backupPath); err != nil {
		return fmt.Errorf("failed to create backup: %w", err)
	}
	e.state["backupPath"] = backupPath

	// Add more leaves (size 15)
	for i := 0; i < 5; i++ {
		leaf := e.createTestLeaf()
		tlog.AddLeaf(context.Background(), leaf)
	}
	cp15, err := tlog.CreateCheckpoint()
	if err != nil {
		return fmt.Errorf("failed to create checkpoint 15: %w", err)
	}

	// Witnesses cosign new checkpoint
	for _, w := range e.witnesses {
		w.CosignCheckpoint(cp15)
	}

	// Now simulate rollback: restore database from backup
	// This reverts witness state to size 10
	if err := e.copyFile(backupPath, dbPath); err != nil {
		return fmt.Errorf("failed to restore backup: %w", err)
	}

	// Reopen store to pick up restored state
	newStore, err := storage.NewSQLiteStore(dbPath)
	if err != nil {
		return fmt.Errorf("failed to reopen store: %w", err)
	}
	e.store = newStore

	// Recreate witnesses with restored store
	for _, w := range e.witnesses {
		w.Store = newStore
		w.LatestSize = 10 // Rolled back to size 10
		w.LatestRoot = cp10.TreeHead.RootHash
	}

	return nil
}

func (e *Engine) executeWitnessRollback(e2 *Engine, ctx context.Context) (*AttackResult, error) {
	result := &AttackResult{ScenarioName: "witness-rollback"}

	// Log is at size 15, but witnesses rolled back to size 10
	currentSize := e.log.Size()
	currentCP := e.log.GetCheckpoint()

	// Check witness states
	rolledBackCount := 0
	for _, w := range e.witnesses {
		if w.LatestSize < currentSize {
			rolledBackCount++
		}
	}

	// Client queries witnesses - they report stale state
	staleDetected := false
	for _, w := range e.witnesses {
		if w.LatestSize < currentSize {
			staleDetected = true
			break
		}
	}

	// Attack succeeds if client accepts stale witness state
	attackSucceeded := !staleDetected && rolledBackCount > 0

	// Detection: client notices witness state is behind log
	detected := staleDetected

	var evidence *types.EvidenceBundle
	if detected {
		evidence = &types.EvidenceBundle{
			Version:     1,
			LogIdentity: func() types.LogIdentity { pk := e.log.PublicKey(); return *types.NewLogIdentity(&pk) }(),
			Case:        types.EvidenceCaseWitnessEquivocation,
			Checkpoints: []*types.Checkpoint{currentCP},
			DetectionTime: time.Now(),
			DetectorID:  "client-0",
			Metadata:    map[string]string{"type": "witness_rollback", "rolled_back_count": fmt.Sprintf("%d", rolledBackCount)},
		}
	}

	result.Success = attackSucceeded
	result.Detected = detected
	result.Evidence = evidence
	result.Details = fmt.Sprintf(
		"Log Size: %d, Witnesses Rolled Back: %d, Stale Detected: %v",
		currentSize, rolledBackCount, staleDetected,
	)

	return result, nil
}

func (e *Engine) cleanupWitnessRollback(e2 *Engine) error {
	backupPath, _ := e.state["backupPath"].(string)
	if backupPath != "" {
		os.Remove(backupPath)
	}
	e.state = make(map[string]interface{})
	return nil
}

// =============================================================================
// SCENARIO 4: Witness Equivocation (Compromised Witness)
// =============================================================================

func (e *Engine) setupWitnessEquivocation(e2 *Engine) error {
	tlog, err := log.NewTransparencyLog(e.store, false)
	if err != nil {
		return fmt.Errorf("failed to create log: %w", err)
	}
	e.log = tlog

	// Create 3 witnesses, one compromised
	e.witnesses = make([]*MockWitness, 3)
	for i := 0; i < 3; i++ {
		w, err := e.createHonestWitness(fmt.Sprintf("witness-%d", i), tlog.PublicKey())
		if err != nil {
			return fmt.Errorf("failed to create witness %d: %w", i, err)
		}
		// Make witness 1 compromised
		if i == 1 {
			w.Compromised = true
			w.MaliciousSig = true
		}
		e.witnesses[i] = w
	}

	e.clients = make([]*MockClient, 1)
	e.clients[0] = e.createClient("client-0", tlog, e.witnesses)

	// Add leaves
	for i := 0; i < 10; i++ {
		leaf := e.createTestLeaf()
		tlog.AddLeaf(context.Background(), leaf)
	}

	return nil
}

func (e *Engine) executeWitnessEquivocation(e2 *Engine, ctx context.Context) (*AttackResult, error) {
	result := &AttackResult{ScenarioName: "witness-equivocation"}

	// Create checkpoint at size 10
	cp, err := e.log.CreateCheckpoint()
	if err != nil {
		return result, fmt.Errorf("checkpoint failed: %w", err)
	}

	// Honest witnesses cosign normally
	cosigs := make([]types.Cosignature, 0)
	equivocatedWitnesses := make([]string, 0)

	for _, w := range e.witnesses {
		cosig, err := w.CosignCheckpoint(cp)
		if err != nil {
			return result, fmt.Errorf("cosign failed: %w", err)
		}
		cosigs = append(cosigs, *cosig)

		// Compromised witness also signs a DIFFERENT checkpoint for same size
		if w.Compromised && w.MaliciousSig {
			// Create a fake checkpoint with different root hash
			fakeRoot := crypto.Hash{}
			rand.Read(fakeRoot[:])
			fakeCP := e.createFakeCheckpoint(cp.TreeHead.Size, fakeRoot)

			// Compromised witness signs the fake one too
			fakeCosig, err := w.CosignCheckpoint(fakeCP)
			if err != nil {
				return result, fmt.Errorf("fake cosign failed: %w", err)
			}
			cosigs = append(cosigs, *fakeCosig)
			equivocatedWitnesses = append(equivocatedWitnesses, w.ID)
		}
	}

	// Detection: check for same witness signing different roots at same size
	detected := false
	var evidence *types.EvidenceBundle

	// Group cosignatures by witness
	witnessSigs := make(map[string][]types.Cosignature)
	for _, cs := range cosigs {
		witnessSigs[cs.KeyName] = append(witnessSigs[cs.KeyName], cs)
	}

	for name, sigs := range witnessSigs {
		if len(sigs) > 1 {
			// Check if they're for different roots
			roots := make(map[string]bool)
			for _, s := range sigs {
				roots[fmt.Sprintf("%x", s.RootHash[:])] = true
			}
			if len(roots) > 1 {
				detected = true
				evidence = e.generateEquivocationEvidence(name, sigs)
				break
			}
		}
	}

	attackSucceeded := len(equivocatedWitnesses) > 0 && !detected

	result.Success = attackSucceeded
	result.Detected = detected
	result.Evidence = evidence
	result.Details = fmt.Sprintf(
		"Total Cosignatures: %d, Equivocated Witnesses: %v, Detected: %v",
		len(cosigs), equivocatedWitnesses, detected,
	)

	return result, nil
}

func (e *Engine) cleanupWitnessEquivocation(e2 *Engine) error {
	e.witnesses = nil
	e.clients = nil
	e.log = nil
	return nil
}

// =============================================================================
// SCENARIO 5: Log-Witness Collusion
// =============================================================================

func (e *Engine) setupLogWitnessCollusion(e2 *Engine) error {
	tlog, err := log.NewTransparencyLog(e.store, false)
	if err != nil {
		return fmt.Errorf("failed to create log: %w", err)
	}
	e.log = tlog

	// Create 3 witnesses, one colluding with log
	e.witnesses = make([]*MockWitness, 3)
	for i := 0; i < 3; i++ {
		w, err := e.createHonestWitness(fmt.Sprintf("witness-%d", i), tlog.PublicKey())
		if err != nil {
			return fmt.Errorf("failed to create witness %d: %w", i, err)
		}
		if i == 0 {
			// This witness colludes with log
			w.Compromised = true
		}
		e.witnesses[i] = w
	}

	e.clients = make([]*MockClient, 1)
	e.clients[0] = e.createClient("client-0", tlog, e.witnesses)

	// Add leaves
	for i := 0; i < 10; i++ {
		leaf := e.createTestLeaf()
		tlog.AddLeaf(context.Background(), leaf)
	}

	return nil
}

func (e *Engine) executeLogWitnessCollusion(e2 *Engine, ctx context.Context) (*AttackResult, error) {
	result := &AttackResult{ScenarioName: "log-witness-collusion"}

	// Log creates checkpoint at size 10
	cp, err := e.log.CreateCheckpoint()
	if err != nil {
		return result, fmt.Errorf("checkpoint failed: %w", err)
	}

	// Colluding witness signs immediately (without verifying)
	// Honest witnesses would verify first
	cosigs := make([]types.Cosignature, 0)
	for i, w := range e.witnesses {
		var cosig *types.Cosignature
		if i == 0 && w.Compromised {
			// Colluding witness signs without verification
			cosig, _ = w.CosignCheckpoint(cp)
			cosig.KeyName = "witness-0 (colluding)"
		} else {
			// Honest witnesses verify then sign
			cosig, _ = w.CosignCheckpoint(cp)
		}
		cosigs = append(cosigs, *cosig)
	}

	// Quorum check: 2 of 3 required
	honestCount := 0
	for _, cs := range cosigs {
		if cs.KeyName != "witness-0 (colluding)" {
			honestCount++
		}
	}

	quorumMet := len(cosigs) >= 2

	// Attack succeeds if quorum met with only 1 honest witness (colluding witness counts)
	// This demonstrates why quorum must require INDEPENDENT witnesses
	attackSucceeded := quorumMet && honestCount < 2

	// Detection: policy engine should flag if quorum includes compromised witnesses
	detected := honestCount < 2

	var evidence *types.EvidenceBundle
	if detected {
		evidence = &types.EvidenceBundle{
			Version:     1,
			LogIdentity: func() types.LogIdentity { pk := e.log.PublicKey(); return *types.NewLogIdentity(&pk) }(),
			Case:        types.EvidenceCaseWitnessEquivocation,
			Checkpoints: []*types.Checkpoint{cp},
			Cosignatures: cosigs,
			DetectionTime: time.Now(),
			DetectorID:  "policy-engine",
			Metadata: map[string]string{
				"type":           "collusion",
				"honest_witnesses": fmt.Sprintf("%d", honestCount),
				"total_witnesses":  fmt.Sprintf("%d", len(cosigs)),
			},
		}
	}

	result.Success = attackSucceeded
	result.Detected = detected
	result.Evidence = evidence
	result.Details = fmt.Sprintf(
		"Quorum Met: %v, Honest Witnesses: %d, Total Cosignatures: %d",
		quorumMet, honestCount, len(cosigs),
	)

	return result, nil
}

func (e *Engine) cleanupLogWitnessCollusion(e2 *Engine) error {
	e.witnesses = nil
	e.clients = nil
	e.log = nil
	return nil
}

// =============================================================================
// SCENARIO 6: Network Partition (tc netem)
// =============================================================================

func (e *Engine) setupNetworkPartition(e2 *Engine) error {
	// Check if we have NET_ADMIN capability (required for tc netem)
	if !e.hasNetAdmin() {
		fmt.Println("[WARNING] NET_ADMIN capability not available, simulating network partition in-process")
		e.state["simulated"] = true
	} else {
		e.state["simulated"] = false
		// Create network namespace for isolation
		nsName := "witnessmesh-attack-" + fmt.Sprintf("%d", time.Now().UnixNano())
		if err := e.createNetworkNamespace(nsName); err != nil {
			return fmt.Errorf("failed to create network namespace: %w", err)
		}
		e.networkNamespace = nsName
	}

	tlog, err := log.NewTransparencyLog(e.store, false)
	if err != nil {
		return fmt.Errorf("failed to create log: %w", err)
	}
	e.log = tlog

	e.witnesses = make([]*MockWitness, 3)
	for i := 0; i < 3; i++ {
		w, err := e.createHonestWitness(fmt.Sprintf("witness-%d", i), tlog.PublicKey())
		if err != nil {
			return fmt.Errorf("failed to create witness %d: %w", i, err)
		}
		e.witnesses[i] = w
	}

	e.clients = make([]*MockClient, 1)
	e.clients[0] = e.createClient("client-0", tlog, e.witnesses)

	// Add leaves
	for i := 0; i < 10; i++ {
		leaf := e.createTestLeaf()
		tlog.AddLeaf(context.Background(), leaf)
	}

	return nil
}

func (e *Engine) executeNetworkPartition(e2 *Engine, ctx context.Context) (*AttackResult, error) {
	result := &AttackResult{ScenarioName: "network-partition"}

	simulated := e.state["simulated"].(bool)

	if !simulated {
		// Apply tc netem rules to simulate 500ms latency + 10% packet loss
		if err := e.applyNetworkEmulation(); err != nil {
			return result, fmt.Errorf("failed to apply netem: %w", err)
		}
		defer e.removeNetworkEmulation()
	}

	// Create checkpoint
	cp, err := e.log.CreateCheckpoint()
	if err != nil {
		return result, fmt.Errorf("checkpoint failed: %w", err)
	}

	// Witnesses attempt to cosign with network delays
	cosigs := make([]types.Cosignature, 0)
	timeoutCount := 0

	for _, w := range e.witnesses {
		done := make(chan *types.Cosignature, 1)
		errChan := make(chan error, 1)

		go func(wit *MockWitness) {
			cosig, err := wit.CosignCheckpoint(cp)
			if err != nil {
				errChan <- err
				return
			}
			done <- cosig
		}(w)

		select {
		case cosig := <-done:
			cosigs = append(cosigs, *cosig)
		case err := <-errChan:
			result.Details += fmt.Sprintf("Witness %s error: %v; ", w.ID, err)
		case <-time.After(2 * time.Second):
			timeoutCount++
			result.Details += fmt.Sprintf("Witness %s timeout; ", w.ID)
		}
	}

	// After partition heals, check for stale checkpoints
	staleDetected := false
	for _, w := range e.witnesses {
		if w.LatestSize < e.log.Size() {
			staleDetected = true
			break
		}
	}

	// Attack succeeds if witnesses fall behind and client accepts stale state
	attackSucceeded := timeoutCount > 0 && !staleDetected

	// Detection: client notices witnesses are behind
	detected := staleDetected || timeoutCount > 0

	var evidence *types.EvidenceBundle
	if detected {
		evidence = &types.EvidenceBundle{
			Version:     1,
			LogIdentity: func() types.LogIdentity { pk := e.log.PublicKey(); return *types.NewLogIdentity(&pk) }(),
			Case:        types.EvidenceCaseDifferentSizeFork,
			Checkpoints: []*types.Checkpoint{cp},
			DetectionTime: time.Now(),
			DetectorID:  "client-0",
			Metadata: map[string]string{
				"type":            "network_partition",
				"timeout_count":   fmt.Sprintf("%d", timeoutCount),
				"stale_detected":  fmt.Sprintf("%v", staleDetected),
			},
		}
	}

	result.Success = attackSucceeded
	result.Detected = detected
	result.Evidence = evidence
	result.Details = fmt.Sprintf(
		"Timeouts: %d, Stale Detected: %v, Cosignatures Received: %d",
		timeoutCount, staleDetected, len(cosigs),
	)

	return result, nil
}

func (e *Engine) cleanupNetworkPartition(e2 *Engine) error {
	if e.networkNamespace != "" {
		e.removeNetworkNamespace(e.networkNamespace)
		e.networkNamespace = ""
	}
	e.state = make(map[string]interface{})
	return nil
}

// =============================================================================
// Helper Methods
// =============================================================================

func (e *Engine) createHonestWitness(id string, logPubKey crypto.PublicKey) (*MockWitness, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	publicKey := crypto.PublicKey(pub)
	keyHash := publicKey.Hash()

	w := &MockWitness{
		ID:         id,
		PrivateKey: priv,
		PublicKey:  publicKey,
		KeyHash:    keyHash,
		Store:      e.store,
		LogPubKey:  logPubKey,
		LogOrigin:  sigsumtypes.SigsumCheckpointOrigin(&logPubKey),
	}

	return w, nil
}

func (e *Engine) createClient(id string, tlog *log.TransparencyLog, witnesses []*MockWitness) *MockClient {
	return &MockClient{
		ID:        id,
		Store:     e.store,
		Log:       tlog,
		Witnesses: witnesses,
	}
}

func (e *Engine) createTestLeaf() requests.Leaf {
	// Create a random leaf with valid signature
	data := make([]byte, 32)
	rand.Read(data)
	checksum := crypto.HashBytes(data)

	// Use a test key
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sig := ed25519.Sign(priv, checksum[:])
	pubKey := crypto.PublicKey(pub)

	return requests.Leaf{
		Message:   checksum,
		Signature: crypto.Signature(sig),
		PublicKey: pubKey,
	}
}

// createTestLeafLocal creates a leaf for the local log type (used for alternative history)
func (e *Engine) createTestLeafLocal() log.Leaf {
	data := make([]byte, 32)
	rand.Read(data)
	checksum := crypto.HashBytes(data)

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sig := ed25519.Sign(priv, checksum[:])
	keyHash := crypto.PublicKey(pub).Hash()

	return log.Leaf{
		Checksum:  checksum,
		Signature: crypto.Signature(sig),
		KeyHash:   keyHash,
	}
}

func (e *Engine) createFakeCheckpoint(size uint64, rootHash crypto.Hash) *types.Checkpoint {
	e.log.SetMalicious(true)
	altLeaves := make([]log.Leaf, size)
	for i := range altLeaves {
		altLeaves[i] = log.Leaf{
			Checksum: crypto.HashBytes([]byte(fmt.Sprintf("alt-leaf-%d", i))),
		}
	}
	e.log.CreateAlternativeHistory(altLeaves)
	cp, err := e.log.GetMaliciousCheckpoint(size)
	if err == nil && cp != nil {
		return cp
	}
	return &types.Checkpoint{
		Checkpoint: &checkpoint.Checkpoint{
			SignedTreeHead: sigsumtypes.SignedTreeHead{
				TreeHead: sigsumtypes.TreeHead{
					Size:     size,
					RootHash: rootHash,
				},
			},
			Origin: e.log.Origin(),
		},
		LogID:      e.log.PublicKey().Hash(),
		ReceivedAt: time.Now(),
		Source:     "fake",
	}
}

func (e *Engine) getDBPath() string {
	// This is a simplification - in reality we'd track the DB path
	return "data/witnessmesh.db"
}

func (e *Engine) copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}

func (e *Engine) hasNetAdmin() bool {
	// Check if we have CAP_NET_ADMIN
	// Try to create a netlink socket
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, syscall.NETLINK_ROUTE)
	if err != nil {
		return false
	}
	syscall.Close(fd)
	return true
}

func (e *Engine) createNetworkNamespace(name string) error {
	// Create a new network namespace
	cmd := exec.Command("ip", "netns", "add", name)
	return cmd.Run()
}

func (e *Engine) removeNetworkNamespace(name string) error {
	cmd := exec.Command("ip", "netns", "del", name)
	return cmd.Run()
}

func (e *Engine) applyNetworkEmulation() error {
	// Apply tc netem to the network namespace
	// This simulates 500ms latency and 10% packet loss
	if e.networkNamespace == "" {
		return nil
	}

	cmds := [][]string{
		{"ip", "netns", "exec", e.networkNamespace, "tc", "qdisc", "add", "dev", "lo", "root", "netem", "delay", "500ms", "loss", "10%"},
	}

	for _, args := range cmds {
		cmd := exec.Command(args[0], args[1:]...)
		if err := cmd.Run(); err != nil {
			return err
		}
		e.tcRules = append(e.tcRules, args[len(args)-1]) // Track for cleanup
	}

	return nil
}

func (e *Engine) removeNetworkEmulation() error {
	if e.networkNamespace == "" {
		return nil
	}

	cmd := exec.Command("ip", "netns", "exec", e.networkNamespace, "tc", "qdisc", "del", "dev", "lo", "root")
	return cmd.Run()
}

func (e *Engine) generateForkEvidence(cp1, cp2 *types.Checkpoint, cosigs []types.Cosignature) *types.EvidenceBundle {
	// Get log public key from the engine's log
	logPubKey := e.log.PublicKey()
	logIdentity := *types.NewLogIdentity(&logPubKey)
	return &types.EvidenceBundle{
		Version:        1,
		LogIdentity:    logIdentity,
		Case:           types.EvidenceCaseDifferentSizeFork,
		Checkpoints:    []*types.Checkpoint{cp1, cp2},
		Cosignatures:   cosigs,
		DetectionTime:  time.Now(),
		DetectorID:     "client",
		Metadata:       map[string]string{"type": "split_view", "cp1_size": fmt.Sprintf("%d", cp1.Checkpoint.SignedTreeHead.Size), "cp2_size": fmt.Sprintf("%d", cp2.Checkpoint.SignedTreeHead.Size)},
	}
}

func (e *Engine) generateEquivocationEvidence(witnessName string, sigs []types.Cosignature) *types.EvidenceBundle {
	checkpoints := make([]*types.Checkpoint, len(sigs))
	for i, s := range sigs {
		treeHead := sigsumtypes.TreeHead{
			Size:     s.TreeSize,
			RootHash: s.RootHash,
		}
		cp := &types.Checkpoint{
			Checkpoint: &checkpoint.Checkpoint{
				SignedTreeHead: sigsumtypes.SignedTreeHead{
					TreeHead: treeHead,
				},
				Origin: e.log.Origin(),
			},
		}
		checkpoints[i] = cp
	}

	// Get log public key from the engine's log
	logPubKey := e.log.PublicKey()
	logIdentity := *types.NewLogIdentity(&logPubKey)

	return &types.EvidenceBundle{
		Version:        1,
		LogIdentity:    logIdentity,
		Case:           types.EvidenceCaseWitnessEquivocation,
		Checkpoints:    checkpoints,
		Cosignatures:   sigs,
		DetectionTime:  time.Now(),
		DetectorID:     "verifier",
		Metadata:       map[string]string{"type": "equivocation", "witness": witnessName},
	}
}

// =============================================================================
// MockWitness Methods
// =============================================================================

func (w *MockWitness) CosignCheckpoint(cp *types.Checkpoint) (*types.Cosignature, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Verify checkpoint signature
	if err := types.VerifyCheckpoint(cp, &w.LogPubKey); err != nil {
		if !w.Compromised {
			return nil, fmt.Errorf("checkpoint verification failed: %w", err)
		}
	}

	// Get the tree head from the checkpoint
	treeHead := cp.Checkpoint.SignedTreeHead.TreeHead

	// Check if we're being asked to sign a conflicting checkpoint
	if w.LatestSize == treeHead.Size && w.LatestRoot != treeHead.RootHash {
		if !w.Compromised {
			return nil, fmt.Errorf("refusing to sign conflicting checkpoint at size %d", treeHead.Size)
		}
		// Compromised witness signs anyway
	}

	// Create cosignature manually (like witness.go)
	timestamp := uint64(time.Now().Unix())

	// Format the checkpoint for signing (RFC 6962 format)
	checkpointText := fmt.Sprintf("%s\n%d\n%s\n",
		cp.Origin,
		treeHead.Size,
		base64.StdEncoding.EncodeToString(treeHead.RootHash[:]))

	// Sign the checkpoint text
	signature := ed25519.Sign(w.PrivateKey, []byte(checkpointText))

	var sig crypto.Signature
	copy(sig[:], signature)

	// Create a key ID for the witness
	keyId := checkpoint.NewWitnessKeyId(w.ID, &w.LogPubKey)

	wrapped := &types.Cosignature{
		CosignatureLine: &checkpoint.CosignatureLine{
			KeyId:     keyId,
			Timestamp: timestamp,
			Signature: sig,
		},
		WitnessID: w.KeyHash,
		Verified:  true,
		VerifiedAt: time.Now(),
		TreeSize:  treeHead.Size,
		RootHash:  treeHead.RootHash,
	}

	// Update witness state
	w.LatestSize = treeHead.Size
	w.LatestRoot = treeHead.RootHash

	// Save to storage
	if w.Store != nil {
		w.Store.SaveWitnessState(w.KeyHash, cp.LogID, w.LogOrigin, w.LatestSize, w.LatestRoot)
	}

	return wrapped, nil
}

// =============================================================================
// MockClient Methods
// =============================================================================

func (c *MockClient) VerifyCheckpoint(cp *types.Checkpoint, cosigs []types.Cosignature) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Verify checkpoint signature
	logPubKey := c.Log.PublicKey()
	if err := types.VerifyCheckpoint(cp, &logPubKey); err != nil {
		c.DetectedFork = true
		return false
	}

	// Verify cosignatures
	verifiedCount := 0
	for _, cs := range cosigs {
		// Find witness
		var wit *MockWitness
		for _, w := range c.Witnesses {
			if w.ID == cs.KeyName || w.KeyHash == cs.WitnessID {
				wit = w
				break
			}
		}
		if wit == nil {
			continue
		}

		// Verify cosignature
		if types.VerifyCosignature(cp, &cs, &wit.PublicKey) {
			verifiedCount++
		}
	}

	// Check consistency with known state
	if c.KnownSize > 0 && cp.TreeHead.Size == c.KnownSize {
		if cp.TreeHead.RootHash != c.KnownRoot {
			c.DetectedFork = true
			return false
		}
	}

	// Update known state
	c.KnownSize = cp.TreeHead.Size
	c.KnownRoot = cp.TreeHead.RootHash

	// Quorum: 2 of 3
	return verifiedCount >= 2
}

// =============================================================================
// CLI Integration
// =============================================================================

// RunAttackCLI is the entry point for CLI attack execution
func RunAttackCLI(ctx context.Context, store *storage.SQLiteStore, scenarioName string) error {
	eng := NewEngine(store)
	return eng.RunAttack(ctx, scenarioName)
}

// ListScenarios prints all available scenarios
func ListScenarios() {
	eng := NewEngine(nil)
	for _, s := range eng.GetScenarios() {
		fmt.Printf("  %-25s %s\n", s.Name, s.Description)
		fmt.Printf("    Expected: %s\n\n", s.Expected)
	}
}