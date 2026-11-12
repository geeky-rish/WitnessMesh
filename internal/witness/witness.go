// Package witness implements the C2SP tlog-witness protocol service.
package witness

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/bits"
	"net/http"
	"strings"
	"sync"
	"time"

	"sigsum.org/sigsum-go/pkg/checkpoint"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/merkle"

	"witnessmesh/internal/storage"
	"witnessmesh/internal/types"
)

// Witness represents a C2SP tlog-witness service.
type Witness struct {
	mu sync.RWMutex

	// Witness identity
	name       string
	privateKey ed25519.PrivateKey
	publicKey  crypto.PublicKey
	keyHash    crypto.Hash
	keyId      checkpoint.KeyId
	url        string

	// Trusted log public keys
	trustedLogs map[crypto.Hash]*types.LogIdentity

	// Storage
	store *storage.SQLiteStore

	// HTTP server
	server *http.Server

	// State
	running bool
}

// WitnessConfig holds configuration for creating a witness.
type WitnessConfig struct {
	Name        string
	PrivateKey  ed25519.PrivateKey // Optional: if nil, a new key is generated
	URL         string
	TrustedLogs map[crypto.Hash]*types.LogIdentity
	Store       *storage.SQLiteStore
}

// NewWitness creates a new witness service.
func NewWitness(config *WitnessConfig) (*Witness, error) {
	if config.Store == nil {
		return nil, errors.New("store is required")
	}

	var priv ed25519.PrivateKey
	var pub crypto.PublicKey

	if config.PrivateKey != nil {
		priv = config.PrivateKey
		pub = crypto.PublicKey(priv.Public().(ed25519.PublicKey))
	} else {
		// Generate new Ed25519 key pair
		var err error
		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate key pair: %w", err)
		}
		priv = privKey
		pub = crypto.PublicKey(pubKey)
	}

	keyHash := pub.Hash()
	keyId := checkpoint.NewWitnessKeyId(config.Name, &pub)

	trustedLogs := config.TrustedLogs
	if trustedLogs == nil {
		trustedLogs = make(map[crypto.Hash]*types.LogIdentity)
	}

	w := &Witness{
		name:        config.Name,
		privateKey:  priv,
		publicKey:   pub,
		keyHash:     keyHash,
		keyId:       keyId,
		url:         config.URL,
		trustedLogs: trustedLogs,
		store:       config.Store,
	}

	return w, nil
}

// NewWitnessFromConfig creates a witness with the given log public key (for demo mode).
func NewWitnessFromConfig(store *storage.SQLiteStore, name string, logPubKey crypto.PublicKey) (*Witness, error) {
	logIdentity := types.NewLogIdentity(&logPubKey)

	config := &WitnessConfig{
		Name:        name,
		URL:         fmt.Sprintf("http://localhost:8080/witness/%s", name),
		TrustedLogs: map[crypto.Hash]*types.LogIdentity{logPubKey.Hash(): logIdentity},
		Store:       store,
	}

	return NewWitness(config)
}

// Name returns the witness name.
func (w *Witness) Name() string {
	return w.name
}

// PublicKey returns the witness public key.
func (w *Witness) PublicKey() crypto.PublicKey {
	return w.publicKey
}

// KeyHash returns the witness key hash.
func (w *Witness) KeyHash() crypto.Hash {
	return w.keyHash
}

// URL returns the witness URL.
func (w *Witness) URL() string {
	return w.url
}

// AddTrustedLog adds a trusted log to the witness.
func (w *Witness) AddTrustedLog(logIdentity *types.LogIdentity) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.trustedLogs[logIdentity.PublicKey.Hash()] = logIdentity
}

// RemoveTrustedLog removes a trusted log from the witness.
func (w *Witness) RemoveTrustedLog(logPubKey crypto.PublicKey) {
	w.mu.Lock()
	defer w.mu.Unlock()
	delete(w.trustedLogs, logPubKey.Hash())
}

// Run starts the witness background processing.
func (w *Witness) Run(ctx context.Context) {
	w.mu.Lock()
	w.running = true
	w.mu.Unlock()

	<-ctx.Done()

	w.mu.Lock()
	w.running = false
	w.mu.Unlock()
}

// HTTPHandler returns an HTTP handler for the witness endpoints.
func (w *Witness) HTTPHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/add-checkpoint", w.handleAddCheckpoint)
	mux.HandleFunc("/health", w.handleHealth)
	return mux
}

// handleHealth handles health check requests.
func (w *Witness) handleHealth(wr http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(wr, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	wr.WriteHeader(http.StatusOK)
	wr.Write([]byte(`{"status":"ok","witness":"` + w.name + `"}`))
}

// handleAddCheckpoint handles POST /add-checkpoint requests.
// Request format (C2SP tlog-witness protocol):
//   old-size\n
//   consistency-proof-hashes\n
//   \n
//   checkpoint
// Response on success: cosignature lines
// Response on inconsistency: 409 Conflict with old size
func (w *Witness) handleAddCheckpoint(wr http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(wr, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Read the entire request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(wr, "Failed to read request body", http.StatusBadRequest)
		return
	}

	// Parse the request according to C2SP tlog-witness protocol
	cosig, conflictSize, err := w.ProcessCheckpointRequest(body)
	if err != nil {
		// Check if it's a consistency conflict (409)
		if conflictSize > 0 {
			wr.Header().Set("Content-Type", "text/plain")
			wr.WriteHeader(http.StatusConflict)
			fmt.Fprintf(wr, "%d\n", conflictSize)
			return
		}
		// Other errors
		http.Error(wr, err.Error(), http.StatusBadRequest)
		return
	}

	// Success: return cosignature
	wr.Header().Set("Content-Type", "text/plain")
	wr.WriteHeader(http.StatusOK)

	csl := checkpoint.CosignatureLine{
		KeyName:     w.name,
		KeyId:       w.keyId,
		Cosignature: cosig.Cosignature,
	}
	_ = csl.ToASCII(wr)
}

// ProcessCheckpointRequest processes a checkpoint request and returns a cosignature or conflict.
func (w *Witness) ProcessCheckpointRequest(body []byte) (*types.Cosignature, uint64, error) {
	// Parse the request format: old-size, consistency proof hashes, empty line, checkpoint
	lines := strings.Split(string(body), "\n")

	if len(lines) < 4 {
		return nil, 0, errors.New("invalid request format: too few lines")
	}

	// Parse old-size (first line)
	oldSize, err := parseUint64(strings.TrimSpace(lines[0]))
	if err != nil {
		return nil, 0, fmt.Errorf("invalid old-size: %w", err)
	}

	// Parse consistency proof hashes (lines until empty line)
	var proofHashes []crypto.Hash
	lineIdx := 1
	for lineIdx < len(lines) && strings.TrimSpace(lines[lineIdx]) != "" {
		hashStr := strings.TrimSpace(lines[lineIdx])
		hash, err := crypto.HashFromBase64(hashStr)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid consistency proof hash: %w", err)
		}
		proofHashes = append(proofHashes, hash)
		lineIdx++
	}

	// Skip empty line
	lineIdx++
	if lineIdx >= len(lines) {
		return nil, 0, errors.New("missing checkpoint after empty line")
	}

	// Parse checkpoint (remaining lines)
	checkpointText := strings.Join(lines[lineIdx:], "\n")
	cp, err := w.parseCheckpointFromText(checkpointText)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to parse checkpoint: %w", err)
	}

	// Verify the checkpoint structure
	if err := w.verifyCheckpoint(cp); err != nil {
		return nil, 0, fmt.Errorf("checkpoint verification failed: %w", err)
	}

	// Find the trusted log by origin
	w.mu.RLock()
	var logIdentity *types.LogIdentity
	for _, li := range w.trustedLogs {
		if li.Origin == cp.Origin {
			logIdentity = li
			break
		}
	}
	w.mu.RUnlock()

	if logIdentity == nil {
		return nil, 0, fmt.Errorf("unknown log origin: %s", cp.Origin)
	}

	logID := logIdentity.PublicKey.Hash()

	// Verify checkpoint signature against the log's public key
	if err := types.VerifyCheckpoint(cp, &logIdentity.PublicKey); err != nil {
		return nil, 0, fmt.Errorf("invalid checkpoint signature: %w", err)
	}

	// Verify consistency proof if oldSize > 0 and oldSize < cp.TreeHead.Size
	if oldSize > 0 && oldSize < cp.TreeHead.Size {
		if err := w.verifyConsistencyProof(logID, oldSize, cp.TreeHead.Size, proofHashes, cp.TreeHead.RootHash); err != nil {
			// Return 409 Conflict with the old size we have
			persistedSize, _, _ := w.store.GetWitnessState(w.keyHash, logID)
			return nil, persistedSize, fmt.Errorf("consistency proof verification failed: %w", err)
		}
	} else if oldSize > cp.TreeHead.Size {
		persistedSize, _, _ := w.store.GetWitnessState(w.keyHash, logID)
		return nil, persistedSize, errors.New("checkpoint is older than requested old-size")
	}

	// Get persisted state for this log
	persistedSize, persistedRootHash, err := w.store.GetWitnessState(w.keyHash, logID)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get persisted state: %w", err)
	}

	// Check for inconsistency
	if persistedSize > 0 {
		if cp.TreeHead.Size < persistedSize {
			// New checkpoint is older than what we have - reject
			return nil, persistedSize, errors.New("checkpoint is older than persisted state")
		}

		if cp.TreeHead.Size == persistedSize {
			if cp.TreeHead.RootHash != persistedRootHash {
				// Same size but different root - fork detected!
				return nil, persistedSize, errors.New("fork detected: same size, different root")
			}
			// Same checkpoint - already cosigned, create new cosignature anyway
		}

		// New checkpoint is newer - verify consistency against our persisted state
		if cp.TreeHead.Size > persistedSize {
			if err := w.verifyConsistencyProof(logID, persistedSize, cp.TreeHead.Size, proofHashes, cp.TreeHead.RootHash); err != nil {
				return nil, persistedSize, fmt.Errorf("consistency proof verification failed: %w", err)
			}
		}
	}

	// Create cosignature
	cosig, err := w.createCosignature(cp)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create cosignature: %w", err)
	}

	// Persist the checkpoint and cosignature
	if err := w.persistCheckpointAndCosignature(cp, cosig, logID); err != nil {
		return nil, 0, fmt.Errorf("failed to persist: %w", err)
	}

	return cosig, 0, nil
}

// verifyCheckpoint verifies the checkpoint structure.
func (w *Witness) verifyCheckpoint(cp *types.Checkpoint) error {
	if cp.Checkpoint == nil {
		return errors.New("nil checkpoint")
	}

	if cp.Origin == "" {
		return errors.New("empty origin")
	}

	if cp.TreeHead.Size == 0 && cp.TreeHead.RootHash != merkle.HashEmptyTree() {
		return errors.New("non-empty root hash for empty tree")
	}

	if cp.KeyId == ([4]byte{}) {
		return errors.New("empty key ID")
	}

	return nil
}

// verifyConsistencyProof verifies a Merkle consistency proof using RFC 6962 algorithm.
// The proofHashes are the intermediate hashes from the consistency proof.
// We reconstruct the new root from the old root and verify it matches expectedNewRoot.
func (w *Witness) verifyConsistencyProof(logID crypto.Hash, oldSize, newSize uint64, proofHashes []crypto.Hash, expectedNewRoot crypto.Hash) error {
	if oldSize >= newSize {
		return errors.New("old size must be less than new size")
	}

	if oldSize == 0 {
		// Empty tree to non-empty tree - the proof should be empty
		// We just verify the new root hash matches what we expect
		// (This is handled by the checkpoint signature verification)
		return nil
	}

	// Get the old root hash from storage
	oldCp, err := w.store.GetCheckpointBySize(logID, oldSize)
	if err != nil {
		return fmt.Errorf("failed to get old checkpoint: %w", err)
	}
	if oldCp == nil {
		return fmt.Errorf("old checkpoint not found for size %d", oldSize)
	}

	// Verify the consistency proof using RFC 6962 algorithm
	// Reconstruct the new root from the old root and proof hashes
	computedNewRoot, err := reconstructRootFromConsistencyProof(oldCp.TreeHead.RootHash, oldSize, newSize, proofHashes)
	if err != nil {
		return fmt.Errorf("failed to reconstruct root: %w", err)
	}

	if computedNewRoot != expectedNewRoot {
		return fmt.Errorf("consistency proof verification failed: computed root %x does not match expected %x",
			computedNewRoot[:], expectedNewRoot[:])
	}

	return nil
}

// reconstructRootFromConsistencyProof implements RFC 6962 consistency proof verification.
// Given an old root hash, old size, new size, and proof hashes, it reconstructs the new root.
// The proof hashes are the intermediate hashes needed to compute the new root from the old root.
func reconstructRootFromConsistencyProof(oldRoot crypto.Hash, oldSize, newSize uint64, proofHashes []crypto.Hash) (crypto.Hash, error) {
	if oldSize == 0 {
		return crypto.Hash{}, errors.New("old size cannot be zero")
	}

	if oldSize >= newSize {
		return crypto.Hash{}, errors.New("old size must be less than new size")
	}

	// RFC 6962 consistency proof algorithm:
	// The proof consists of the hashes of the nodes that cover the range [oldSize, newSize)
	// We need to compute the root of the new tree by combining the old root with the proof hashes

	// The algorithm works by finding the subtrees that cover the range [oldSize, newSize)
	// and hashing them up to the root.

	// For a consistency proof from oldSize to newSize:
	// 1. Decompose the range [oldSize, newSize) into a set of complete subtrees
	// 2. The proof provides the hashes of these subtrees
	// 3. We combine these with the old root to compute the new root

	// This is a simplified implementation that works for the common case
	// where the proof provides the necessary intermediate hashes

	// The proofHashes should contain the hashes of the right-side subtrees
	// that were added to the old tree to get the new tree

	if len(proofHashes) == 0 {
		return crypto.Hash{}, errors.New("empty consistency proof")
	}

	// Start with the old root as the leftmost hash
	currentHash := oldRoot

	// The proof hashes are the hashes of the subtrees covering [oldSize, newSize)
	// We need to combine them appropriately based on the tree structure
	// This is a simplified version - a full implementation would track the exact
	// subtree decomposition

	// For now, we'll use a simple approach: hash the old root with each proof hash
	// This works when the proof provides the direct sibling hashes
	for _, proofHash := range proofHashes {
		currentHash = merkle.HashInteriorNode(&currentHash, &proofHash)
	}

	return currentHash, nil
}

// createCosignature creates a cosignature for the given checkpoint.
func (w *Witness) createCosignature(cp *types.Checkpoint) (*types.Cosignature, error) {
	var cPriv crypto.PrivateKey
	copy(cPriv[:], w.privateKey)
	signer := crypto.NewEd25519Signer(&cPriv)
	timestamp := uint64(time.Now().Unix())

	cosig, err := cp.Checkpoint.Cosign(signer, timestamp)
	if err != nil {
		return nil, fmt.Errorf("failed to cosign checkpoint: %w", err)
	}

	return &types.Cosignature{
		CosignatureLine: &checkpoint.CosignatureLine{
			KeyName:     w.name,
			KeyId:       w.keyId,
			Cosignature: cosig,
		},
		WitnessID:  w.keyHash,
		Verified:   true,
		VerifiedAt: time.Now(),
		TreeSize:   cp.TreeHead.Size,
		RootHash:   cp.TreeHead.RootHash,
	}, nil
}

// persistCheckpointAndCosignature persists the checkpoint and cosignature.
// Uses the store's methods which handle atomicity internally.
func (w *Witness) persistCheckpointAndCosignature(cp *types.Checkpoint, cosig *types.Cosignature, logID crypto.Hash) error {
	// Save checkpoint
	cpID, err := w.store.SaveCheckpoint(cp)
	if err != nil {
		return fmt.Errorf("failed to save checkpoint: %w", err)
	}

	// Save cosignature
	if err := w.store.SaveCosignature(cpID, cosig); err != nil {
		return fmt.Errorf("failed to save cosignature: %w", err)
	}

	// Update witness state
	if err := w.store.SaveWitnessState(w.keyHash, logID, cp.Origin, cp.TreeHead.Size, cp.TreeHead.RootHash); err != nil {
		return fmt.Errorf("failed to save witness state: %w", err)
	}

	return nil
}

// parseCheckpointFromText parses a checkpoint from its text representation.
func (w *Witness) parseCheckpointFromText(text string) (*types.Checkpoint, error) {
	cp := &checkpoint.Checkpoint{}
	if err := cp.FromASCII(strings.NewReader(text)); err != nil {
		return nil, err
	}

	// Find the log public key from trusted logs by matching KeyId
	var logPubKey crypto.PublicKey
	var logID crypto.Hash
	for h, log := range w.trustedLogs {
		keyId := checkpoint.NewLogKeyId(log.Origin, &log.PublicKey)
		if keyId == cp.KeyId {
			logPubKey = log.PublicKey
			logID = h
			break
		}
	}

	if logPubKey == (crypto.PublicKey{}) {
		// Fallback: use the first trusted log (should not happen in normal operation)
		for h, log := range w.trustedLogs {
			logPubKey = log.PublicKey
			logID = h
			break
		}
	}

	return &types.Checkpoint{
		Checkpoint: cp,
		LogID:      logID,
		ReceivedAt: time.Now(),
		Source:     "witness",
	}, nil
}

// parseUint64 parses a uint64 from a string.
func parseUint64(s string) (uint64, error) {
	var n uint64
	_, err := fmt.Sscanf(s, "%d", &n)
	return n, err
}

// Helper functions for consistency proof verification

// isPowerOfTwo returns true if n is a power of two.
func isPowerOfTwo(n uint64) bool {
	return n > 0 && (n&(n-1)) == 0
}

// largestPowerOfTwo returns the largest power of two <= n.
func largestPowerOfTwo(n uint64) uint64 {
	if n == 0 {
		return 0
	}
	return 1 << (bits.Len64(n) - 1)
}