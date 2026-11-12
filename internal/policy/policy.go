// Package policy implements the trust policy engine for the witness mesh.
// It manages the trusted witness set, quorum requirements, witness exclusion
// based on equivocation evidence, and policy change auditing.
package policy

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"gopkg.in/yaml.v3"
)

// WitnessID uniquely identifies a witness in the mesh.
type WitnessID string

// Witness represents a trusted witness in the mesh.
type Witness struct {
	ID          WitnessID       `json:"id" yaml:"id"`
	PublicKey   string          `json:"public_key" yaml:"public_key"`
	Endpoint    string          `json:"endpoint" yaml:"endpoint"`
	Metadata    json.RawMessage `json:"metadata,omitempty" yaml:"metadata,omitempty"`
	AddedAt     time.Time       `json:"added_at" yaml:"added_at"`
	ExcludedAt  *time.Time      `json:"excluded_at,omitempty" yaml:"excluded_at,omitempty"`
	ExclusionID string          `json:"exclusion_id,omitempty" yaml:"exclusion_id,omitempty"`
}

// QuorumPolicy defines the quorum requirements for checkpoint validation.
// For a flat policy with n witnesses, quorum size k, at most f Byzantine witnesses:
//
// Safety condition: 2k - n > f  (equivalently: k > (n + f) / 2)
//   This ensures that any two quorums of size k must intersect in at least one
//   honest witness, preventing forks. If two quorums Q1 and Q2 both sign
//   conflicting checkpoints, their intersection must contain at least one honest
//   witness, which would have to equivocate (sign both). Since we assume at most
//   f Byzantine witnesses, the intersection of honest witnesses is at least
//   2k - n - f > 0, so safety holds.
//
// Liveness condition: k <= n - f
//   This ensures that a quorum can be formed even if all f Byzantine witnesses
//   are unresponsive. The honest witnesses (n - f) must be sufficient to form
//   a quorum.
//
// Assumptions behind these conditions:
// 1. Independence: Witnesses fail independently (no correlated failures).
// 2. Identifiability: Witnesses can be uniquely identified and their signatures verified.
// 3. Bounded Byzantine: At most f witnesses behave arbitrarily (equivocate, lie, etc.).
// 4. Synchrony for liveness: Messages eventually arrive (partial synchrony).
// 5. No shared infrastructure: Quorum arithmetic alone does NOT protect against
//    correlated failures from shared cloud providers, network paths, power grids, etc.
//    Deployments MUST consider infrastructure diversity in witness selection.
//
// Example: n=7, f=2 -> Safety: k > 4.5 => k>=5. Liveness: k <= 5. So k=5.
type QuorumPolicy struct {
	// N is the total number of witnesses in the trusted set.
	N int `json:"n" yaml:"n"`
	// K is the required quorum size (minimum signatures for a valid checkpoint).
	K int `json:"k" yaml:"k"`
	// F is the maximum number of Byzantine witnesses tolerated.
	F int `json:"f" yaml:"f"`
}

// Validate checks that the quorum policy parameters satisfy safety and liveness.
func (q *QuorumPolicy) Validate() error {
	if q.N <= 0 {
		return errors.New("n must be positive")
	}
	if q.K <= 0 {
		return errors.New("k must be positive")
	}
	if q.F < 0 {
		return errors.New("f must be non-negative")
	}
	if q.K > q.N {
		return fmt.Errorf("k (%d) cannot exceed n (%d)", q.K, q.N)
	}
	if q.F >= q.N {
		return fmt.Errorf("f (%d) must be less than n (%d)", q.F, q.N)
	}

	// Safety condition: 2k - n > f
	safety := 2*q.K - q.N
	if safety <= q.F {
		return fmt.Errorf("safety violation: 2k-n=%d not > f=%d (need k > (n+f)/2 = %.1f)", safety, q.F, float64(q.N+q.F)/2)
	}

	// Liveness condition: k <= n - f
	liveness := q.N - q.F
	if q.K > liveness {
		return fmt.Errorf("liveness violation: k=%d > n-f=%d", q.K, liveness)
	}

	return nil
}

// QuorumStatus describes whether a quorum can be achieved.
type QuorumStatus string

const (
	QuorumStatusSafe       QuorumStatus = "safe"        // Policy satisfied, quorum achievable
	QuorumStatusUnsafe     QuorumStatus = "unsafe"      // Safety violated
	QuorumStatusUnavailable QuorumStatus = "unavailable" // Liveness violated (insufficient honest witnesses)
)

// CheckQuorum evaluates whether the current witness set satisfies the quorum policy.
// Returns the status and the number of available (non-excluded) witnesses.
func (q QuorumPolicy) CheckQuorum(availableWitnesses int) (QuorumStatus, int) {
	if availableWitnesses < 0 {
		availableWitnesses = 0
	}

	// Check safety: 2k - availableWitnesses > f
	// We use availableWitnesses as the effective n
	safety := 2*q.K - availableWitnesses
	if safety <= q.F {
		return QuorumStatusUnsafe, availableWitnesses
	}

	// Check liveness: k <= availableWitnesses - f
	liveness := availableWitnesses - q.F
	if q.K > liveness {
		return QuorumStatusUnavailable, availableWitnesses
	}

	return QuorumStatusSafe, availableWitnesses
}

// PolicyConfig represents the complete policy configuration loadable from YAML/JSON.
type PolicyConfig struct {
	Version    string         `json:"version" yaml:"version"`
	Quorum     QuorumPolicy   `json:"quorum" yaml:"quorum"`
	Witnesses  []Witness      `json:"witnesses" yaml:"witnesses"`
	UpdatedAt  time.Time      `json:"updated_at" yaml:"updated_at"`
	UpdatedBy  string         `json:"updated_by" yaml:"updated_by"`
}

// IncidentType represents the type of policy incident.
type IncidentType string

const (
	IncidentTypeWitnessAdded       IncidentType = "witness_added"
	IncidentTypeWitnessExcluded    IncidentType = "witness_excluded"
	IncidentTypeQuorumUpdated      IncidentType = "quorum_updated"
	IncidentTypePolicyReloaded     IncidentType = "policy_reloaded"
	IncidentTypeCheckpointValidated IncidentType = "checkpoint_validated"
	IncidentTypeCheckpointRejected IncidentType = "checkpoint_rejected"
)

// IncidentRecord represents an append-only audit log entry.
type IncidentRecord struct {
	ID        string         `json:"id"`
	Type      IncidentType   `json:"type"`
	Timestamp time.Time      `json:"timestamp"`
	Actor     string         `json:"actor"`
	Details   json.RawMessage `json:"details"`
	PrevHash  string         `json:"prev_hash"` // Hash of previous record for tamper evidence
	Hash      string         `json:"hash"`      // Hash of this record
}

// EvidenceVerifier is the interface for verifying equivocation evidence.
// Implementations should verify cryptographic proofs of witness misbehavior.
type EvidenceVerifier interface {
	// VerifyEquivocation checks if the evidence proves the witness equivocated.
	// Returns the witness ID if verified, empty string otherwise.
	VerifyEquivocation(ctx context.Context, evidence []byte) (WitnessID, error)
}

// PolicyEngine manages the trust policy, witness set, and audit log.
type PolicyEngine struct {
	mu           sync.RWMutex
	config       PolicyConfig
	db           *sql.DB
	evidenceVerifier EvidenceVerifier
	lastHash     string // Hash of last incident record for chaining
}

// NewPolicyEngine creates a new policy engine with the given configuration and database.
func NewPolicyEngine(config PolicyConfig, dbPath string, verifier EvidenceVerifier) (*PolicyEngine, error) {
	if err := config.Quorum.Validate(); err != nil {
		return nil, fmt.Errorf("invalid quorum policy: %w", err)
	}

	if len(config.Witnesses) != config.Quorum.N {
		return nil, fmt.Errorf("witness count (%d) does not match quorum n (%d)", len(config.Witnesses), config.Quorum.N)
	}

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	if err := initSchema(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	engine := &PolicyEngine{
		config:           config,
		db:               db,
		evidenceVerifier: verifier,
	}

	// Check if database already has a persisted config
	var savedConfigJSON string
	err = db.QueryRow(`SELECT config_json FROM policy_config WHERE id = 1`).Scan(&savedConfigJSON)
	if err == nil && savedConfigJSON != "" {
		var persisted PolicyConfig
		if jsonErr := json.Unmarshal([]byte(savedConfigJSON), &persisted); jsonErr == nil {
			engine.config = persisted
		}
	} else {
		// Persist initial config if database is empty
		if err := engine.persistConfig(); err != nil {
			db.Close()
			return nil, fmt.Errorf("failed to persist initial config: %w", err)
		}
	}

	// Load last hash from database for audit chain continuity
	lastHash, err := engine.getLastIncidentHash()
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to load last incident hash: %w", err)
	}
	engine.lastHash = lastHash

	return engine, nil
}

// initSchema creates the necessary database tables.
func initSchema(db *sql.DB) error {
	schema := `
	CREATE TABLE IF NOT EXISTS policy_config (
		id INTEGER PRIMARY KEY CHECK (id = 1),
		config_json TEXT NOT NULL,
		updated_at TEXT NOT NULL,
		updated_by TEXT NOT NULL
	);
	CREATE TABLE IF NOT EXISTS incident_log (
		id TEXT PRIMARY KEY,
		type TEXT NOT NULL,
		timestamp TEXT NOT NULL,
		actor TEXT NOT NULL,
		details TEXT NOT NULL,
		prev_hash TEXT NOT NULL,
		hash TEXT NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_incident_timestamp ON incident_log(timestamp);
	CREATE INDEX IF NOT EXISTS idx_incident_type ON incident_log(type);
	`
	_, err := db.Exec(schema)
	return err
}

// LoadFromConfig loads policy configuration from a YAML or JSON file.
func LoadFromConfig(filePath string) (PolicyConfig, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return PolicyConfig{}, fmt.Errorf("failed to read config file: %w", err)
	}

	var config PolicyConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		// Try JSON if YAML fails
		if err := json.Unmarshal(data, &config); err != nil {
			return PolicyConfig{}, fmt.Errorf("failed to parse config (tried YAML and JSON): %w", err)
		}
	}

	if config.Version == "" {
		config.Version = "1.0"
	}
	if config.UpdatedAt.IsZero() {
		config.UpdatedAt = time.Now().UTC()
	}
	if config.UpdatedBy == "" {
		config.UpdatedBy = "system"
	}

	return config, nil
}

// GetConfig returns a copy of the current policy configuration.
func (e *PolicyEngine) GetConfig() PolicyConfig {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.config
}

// GetWitnesses returns the current trusted witness set (non-excluded).
func (e *PolicyEngine) GetWitnesses() []Witness {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var active []Witness
	for _, w := range e.config.Witnesses {
		if w.ExcludedAt == nil {
			active = append(active, w)
		}
	}
	return active
}

// GetAllWitnesses returns all witnesses including excluded ones.
func (e *PolicyEngine) GetAllWitnesses() []Witness {
	e.mu.RLock()
	defer e.mu.RUnlock()

	result := make([]Witness, len(e.config.Witnesses))
	copy(result, e.config.Witnesses)
	return result
}

// GetQuorumPolicy returns the current quorum policy.
func (e *PolicyEngine) GetQuorumPolicy() QuorumPolicy {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.config.Quorum
}

// ValidateWitnessParticipation checks if a set of witness signatures satisfies the quorum.
// It verifies that all signers are in the current trusted set and not excluded.
func (e *PolicyEngine) ValidateWitnessParticipation(signerIDs []WitnessID) (bool, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	activeWitnesses := make(map[WitnessID]struct{})
	for _, w := range e.config.Witnesses {
		if w.ExcludedAt == nil {
			activeWitnesses[w.ID] = struct{}{}
		}
	}

	// Count valid unique signers
	validSigners := make(map[WitnessID]struct{})
	for _, id := range signerIDs {
		if _, ok := activeWitnesses[id]; !ok {
			return false, fmt.Errorf("signer %s not in trusted set or excluded", id)
		}
		validSigners[id] = struct{}{}
	}

	return len(validSigners) >= e.config.Quorum.K, nil
}

// ExcludeWitness excludes a witness based on verified equivocation evidence.
// This is the primary mechanism for removing Byzantine witnesses from the trusted set.
func (e *PolicyEngine) ExcludeWitness(ctx context.Context, evidence []byte, actor string) (WitnessID, error) {
	// Verify the evidence first
	witnessID, err := e.evidenceVerifier.VerifyEquivocation(ctx, evidence)
	if err != nil {
		return "", fmt.Errorf("evidence verification failed: %w", err)
	}
	if witnessID == "" {
		return "", errors.New("evidence does not prove equivocation")
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	// Find and mark witness as excluded
	found := false
	for i, w := range e.config.Witnesses {
		if w.ID == witnessID {
			if w.ExcludedAt != nil {
				return "", fmt.Errorf("witness %s already excluded", witnessID)
			}
			now := time.Now().UTC()
			e.config.Witnesses[i].ExcludedAt = &now
			e.config.Witnesses[i].ExclusionID = uuid.New().String()
			found = true
			break
		}
	}

	if !found {
		return "", fmt.Errorf("witness %s not found in trusted set", witnessID)
	}

	// Record incident
	details := map[string]interface{}{
		"witness_id":   witnessID,
		"exclusion_id": e.config.Witnesses[0].ExclusionID, // Will be updated below
		"evidence_hash": fmt.Sprintf("%x", evidence[:min(len(evidence), 32)]),
	}
	detailsJSON, _ := json.Marshal(details)

	incident := IncidentRecord{
		ID:        uuid.New().String(),
		Type:      IncidentTypeWitnessExcluded,
		Timestamp: time.Now().UTC(),
		Actor:     actor,
		Details:   detailsJSON,
		PrevHash:  e.lastHash,
	}
	incident.Hash = computeHash(incident)
	e.lastHash = incident.Hash

	// Persist changes
	if err := e.persistConfig(); err != nil {
		return "", fmt.Errorf("failed to persist config: %w", err)
	}
	if err := e.appendIncident(incident); err != nil {
		return "", fmt.Errorf("failed to append incident: %w", err)
	}

	return witnessID, nil
}

// AddWitness adds a new witness to the trusted set and updates quorum parameters.
// This increases n and may require adjusting k to maintain safety/liveness.
func (e *PolicyEngine) AddWitness(witness Witness, actor string) error {
	if witness.ID == "" {
		return errors.New("witness ID cannot be empty")
	}
	if witness.PublicKey == "" {
		return errors.New("witness public key cannot be empty")
	}
	if witness.Endpoint == "" {
		return errors.New("witness endpoint cannot be empty")
	}
	witness.AddedAt = time.Now().UTC()

	e.mu.Lock()
	defer e.mu.Unlock()

	// Check for duplicate
	for _, w := range e.config.Witnesses {
		if w.ID == witness.ID {
			return fmt.Errorf("witness %s already exists", witness.ID)
		}
	}

	// Add witness
	e.config.Witnesses = append(e.config.Witnesses, witness)
	e.config.Quorum.N = len(e.config.Witnesses)
	e.config.UpdatedAt = time.Now().UTC()
	e.config.UpdatedBy = actor

	// Validate new quorum parameters
	if err := e.config.Quorum.Validate(); err != nil {
		// Rollback
		e.config.Witnesses = e.config.Witnesses[:len(e.config.Witnesses)-1]
		e.config.Quorum.N = len(e.config.Witnesses)
		return fmt.Errorf("new quorum policy invalid: %w", err)
	}

	// Record incident
	details := map[string]interface{}{
		"witness_id": witness.ID,
		"new_n":      e.config.Quorum.N,
		"new_k":      e.config.Quorum.K,
		"new_f":      e.config.Quorum.F,
	}
	detailsJSON, _ := json.Marshal(details)

	incident := IncidentRecord{
		ID:        uuid.New().String(),
		Type:      IncidentTypeWitnessAdded,
		Timestamp: time.Now().UTC(),
		Actor:     actor,
		Details:   detailsJSON,
		PrevHash:  e.lastHash,
	}
	incident.Hash = computeHash(incident)
	e.lastHash = incident.Hash

	// Persist changes
	if err := e.persistConfig(); err != nil {
		return fmt.Errorf("failed to persist config: %w", err)
	}
	if err := e.appendIncident(incident); err != nil {
		return fmt.Errorf("failed to append incident: %w", err)
	}

	return nil
}

// UpdateQuorum updates the quorum parameters (k and/or f) with validation.
func (e *PolicyEngine) UpdateQuorum(newK, newF int, actor string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	oldK, oldF := e.config.Quorum.K, e.config.Quorum.F
	e.config.Quorum.K = newK
	e.config.Quorum.F = newF
	e.config.UpdatedAt = time.Now().UTC()
	e.config.UpdatedBy = actor

	if err := e.config.Quorum.Validate(); err != nil {
		e.config.Quorum.K, e.config.Quorum.F = oldK, oldF
		return fmt.Errorf("invalid quorum parameters: %w", err)
	}

	details := map[string]interface{}{
		"old_k": oldK, "new_k": newK,
		"old_f": oldF, "new_f": newF,
		"n":     e.config.Quorum.N,
	}
	detailsJSON, _ := json.Marshal(details)

	incident := IncidentRecord{
		ID:        uuid.New().String(),
		Type:      IncidentTypeQuorumUpdated,
		Timestamp: time.Now().UTC(),
		Actor:     actor,
		Details:   detailsJSON,
		PrevHash:  e.lastHash,
	}
	incident.Hash = computeHash(incident)
	e.lastHash = incident.Hash

	if err := e.persistConfig(); err != nil {
		return fmt.Errorf("failed to persist config: %w", err)
	}
	if err := e.appendIncident(incident); err != nil {
		return fmt.Errorf("failed to append incident: %w", err)
	}

	return nil
}

// CheckpointValidationResult represents the result of validating a checkpoint.
type CheckpointValidationResult struct {
	Valid       bool
	Status      QuorumStatus
	SignerCount int
	RequiredK   int
	AvailableN  int
	Message     string
}

// ValidateCheckpoint validates a checkpoint against the current policy.
// It checks witness participation and quorum satisfaction.
func (e *PolicyEngine) ValidateCheckpoint(signerIDs []WitnessID) CheckpointValidationResult {
	e.mu.RLock()
	defer e.mu.RUnlock()

	activeCount := 0
	for _, w := range e.config.Witnesses {
		if w.ExcludedAt == nil {
			activeCount++
		}
	}

	status, available := e.config.Quorum.CheckQuorum(activeCount)

	valid, err := e.validateSignersUnlocked(signerIDs)
	if err != nil {
		return CheckpointValidationResult{
			Valid:       false,
			Status:      status,
			SignerCount: 0,
			RequiredK:   e.config.Quorum.K,
			AvailableN:  available,
			Message:     err.Error(),
		}
	}

	if !valid {
		return CheckpointValidationResult{
			Valid:       false,
			Status:      status,
			SignerCount: len(signerIDs),
			RequiredK:   e.config.Quorum.K,
			AvailableN:  available,
			Message:     fmt.Sprintf("insufficient signers: got %d, need %d", len(signerIDs), e.config.Quorum.K),
		}
	}

	if status != QuorumStatusSafe {
		return CheckpointValidationResult{
			Valid:       false,
			Status:      status,
			SignerCount: len(signerIDs),
			RequiredK:   e.config.Quorum.K,
			AvailableN:  available,
			Message:     fmt.Sprintf("quorum policy not satisfied: %s", status),
		}
	}

	return CheckpointValidationResult{
		Valid:       true,
		Status:      status,
		SignerCount: len(signerIDs),
		RequiredK:   e.config.Quorum.K,
		AvailableN:  available,
		Message:     "checkpoint valid",
	}
}

// validateSignersUnlocked checks signers without acquiring lock (caller must hold lock).
func (e *PolicyEngine) validateSignersUnlocked(signerIDs []WitnessID) (bool, error) {
	activeWitnesses := make(map[WitnessID]struct{})
	for _, w := range e.config.Witnesses {
		if w.ExcludedAt == nil {
			activeWitnesses[w.ID] = struct{}{}
		}
	}

	validSigners := make(map[WitnessID]struct{})
	for _, id := range signerIDs {
		if _, ok := activeWitnesses[id]; !ok {
			return false, fmt.Errorf("signer %s not in trusted set or excluded", id)
		}
		validSigners[id] = struct{}{}
	}

	return len(validSigners) >= e.config.Quorum.K, nil
}

// RecordCheckpointValidation records the result of checkpoint validation in the audit log.
func (e *PolicyEngine) RecordCheckpointValidation(result CheckpointValidationResult, checkpointHash string, actor string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	incidentType := IncidentTypeCheckpointValidated
	if !result.Valid {
		incidentType = IncidentTypeCheckpointRejected
	}

	details := map[string]interface{}{
		"checkpoint_hash": checkpointHash,
		"valid":           result.Valid,
		"status":          result.Status,
		"signer_count":    result.SignerCount,
		"required_k":      result.RequiredK,
		"available_n":     result.AvailableN,
		"message":         result.Message,
	}
	detailsJSON, _ := json.Marshal(details)

	incident := IncidentRecord{
		ID:        uuid.New().String(),
		Type:      incidentType,
		Timestamp: time.Now().UTC(),
		Actor:     actor,
		Details:   detailsJSON,
		PrevHash:  e.lastHash,
	}
	incident.Hash = computeHash(incident)
	e.lastHash = incident.Hash

	return e.appendIncident(incident)
}

// GetIncidentLog retrieves incident records with optional filtering.
func (e *PolicyEngine) GetIncidentLog(limit int, incidentType IncidentType) ([]IncidentRecord, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	query := `SELECT id, type, timestamp, actor, details, prev_hash, hash FROM incident_log`
	args := []interface{}{}

	if incidentType != "" {
		query += ` WHERE type = ?`
		args = append(args, incidentType)
	}
	query += ` ORDER BY timestamp DESC`
	if limit > 0 {
		query += ` LIMIT ?`
		args = append(args, limit)
	}

	rows, err := e.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var incidents []IncidentRecord
	for rows.Next() {
		var inc IncidentRecord
		var timeStr string
		var detailsStr string
		if err := rows.Scan(&inc.ID, &inc.Type, &timeStr, &inc.Actor, &detailsStr, &inc.PrevHash, &inc.Hash); err != nil {
			return nil, err
		}
		inc.Timestamp, _ = time.Parse(time.RFC3339Nano, timeStr)
		inc.Details = json.RawMessage(detailsStr)
		incidents = append(incidents, inc)
	}
	return incidents, rows.Err()
}

// VerifyAuditChain verifies the integrity of the incident log hash chain.
func (e *PolicyEngine) VerifyAuditChain() error {
	e.mu.RLock()
	defer e.mu.RUnlock()

	rows, err := e.db.Query(`SELECT id, type, timestamp, actor, details, prev_hash, hash FROM incident_log ORDER BY timestamp ASC`)
	if err != nil {
		return err
	}
	defer rows.Close()

	var prevHash string
	for rows.Next() {
		var inc IncidentRecord
		var timeStr string
		var detailsStr string
		if err := rows.Scan(&inc.ID, &inc.Type, &timeStr, &inc.Actor, &detailsStr, &inc.PrevHash, &inc.Hash); err != nil {
			return err
		}
		inc.Timestamp, _ = time.Parse(time.RFC3339Nano, timeStr)
		inc.Details = json.RawMessage(detailsStr)

		if inc.PrevHash != prevHash {
			return fmt.Errorf("hash chain broken at incident %s: expected prev_hash %s, got %s", inc.ID, prevHash, inc.PrevHash)
		}

		expectedHash := computeHash(inc)
		if inc.Hash != expectedHash {
			return fmt.Errorf("hash mismatch at incident %s: expected %s, got %s", inc.ID, expectedHash, inc.Hash)
		}

		prevHash = inc.Hash
	}
	return rows.Err()
}

// Close closes the policy engine and database connection.
func (e *PolicyEngine) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.db.Close()
}

// persistConfig saves the current config to the database.
func (e *PolicyEngine) persistConfig() error {
	configJSON, err := json.Marshal(e.config)
	if err != nil {
		return err
	}

	_, err = e.db.Exec(
		`INSERT OR REPLACE INTO policy_config (id, config_json, updated_at, updated_by) VALUES (1, ?, ?, ?)`,
		string(configJSON), e.config.UpdatedAt.UTC().Format(time.RFC3339Nano), e.config.UpdatedBy,
	)
	return err
}

// appendIncident adds an incident record to the database.
func (e *PolicyEngine) appendIncident(inc IncidentRecord) error {
	_, err := e.db.Exec(
		`INSERT INTO incident_log (id, type, timestamp, actor, details, prev_hash, hash) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		inc.ID, inc.Type, inc.Timestamp.UTC().Format(time.RFC3339Nano), inc.Actor, string(inc.Details), inc.PrevHash, inc.Hash,
	)
	return err
}

// getLastIncidentHash retrieves the hash of the most recent incident.
func (e *PolicyEngine) getLastIncidentHash() (string, error) {
	var hash sql.NullString
	err := e.db.QueryRow(`SELECT hash FROM incident_log ORDER BY timestamp DESC LIMIT 1`).Scan(&hash)
	if err == sql.ErrNoRows {
		return "", nil // Empty log
	}
	if err != nil {
		return "", err
	}
	return hash.String, nil
}

// computeHash computes a deterministic hash of an incident record for chaining.
func computeHash(inc IncidentRecord) string {
	// debug
	// fmt.Printf("DEBUG computeHash: id=%s time=%s details=%s\n", inc.ID, inc.Timestamp.UTC().Format(time.RFC3339Nano), string(inc.Details))

	// Use a simple but deterministic hash for chaining
	// In production, use a cryptographic hash (SHA-256)
	data := fmt.Sprintf("%s|%s|%s|%s|%s|%s",
		inc.ID, inc.Type, inc.Timestamp.UTC().Format(time.RFC3339Nano),
		inc.Actor, string(inc.Details), inc.PrevHash)

	// Simple FNV-1a hash for demonstration; replace with crypto/sha256 in production
	h := uint64(14695981039346656037)
	for i := 0; i < len(data); i++ {
		h ^= uint64(data[i])
		h *= 1099511628211
	}
	return fmt.Sprintf("%016x", h)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}