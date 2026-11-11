// Package log implements the transparency log service.
package log

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"sigsum.org/sigsum-go/pkg/api"
	"sigsum.org/sigsum-go/pkg/checkpoint"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/merkle"
	"sigsum.org/sigsum-go/pkg/requests"
	"sigsum.org/sigsum-go/pkg/server"
	"sigsum.org/sigsum-go/pkg/types"

	"witnessmesh/internal/storage"
	"witnessmesh/internal/types"
)

const (
	EndpointGetTreeHead      = "/tree-head"
	EndpointGetInclusionProof = "/inclusion-proof"
	EndpointGetConsistencyProof = "/consistency-proof"
	EndpointGetLeaves        = "/leaves"
	EndpointAddLeaf          = "/add-leaf"
)

// Leaf represents a log entry
type Leaf struct {
	Checksum crypto.Hash
	Signature crypto.Signature
	KeyHash  crypto.Hash
}

// TransparencyLog implements the transparency log
type TransparencyLog struct {
	mu           sync.RWMutex
	privateKey   ed25519.PrivateKey
	publicKey    crypto.PublicKey
	origin       string
	leaves       []Leaf
	treeHeads    []types.TreeHead
	checkpoints  []*types.Checkpoint
	store        *storage.SQLiteStore
	malicious    bool
	maliciousMu  sync.Mutex
	altLeaves    []Leaf // Alternative history for split-view attack
	altTreeHeads []types.TreeHead
}

// NewTransparencyLog creates a new transparency log
func NewTransparencyLog(store *storage.SQLiteStore, malicious bool) (*TransparencyLog, error) {
	// Generate Ed25519 key pair
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	publicKey := crypto.PublicKey(pub)
	origin := types.SigsumCheckpointOrigin(&publicKey)

	log := &TransparencyLog{
		privateKey:   priv,
		publicKey:    publicKey,
		origin:       origin,
		leaves:       make([]Leaf, 0),
		treeHeads:    make([]types.TreeHead, 1), // Index 0 is empty tree
		checkpoints:  make([]*types.Checkpoint, 0),
		store:        store,
		malicious:    malicious,
		altLeaves:    make([]Leaf, 0),
		altTreeHeads: make([]types.TreeHead, 1),
	}

	// Initialize empty tree head
	log.treeHeads[0] = types.NewEmptyTreeHead()
	log.altTreeHeads[0] = types.NewEmptyTreeHead()

	return log, nil
}

// NewTransparencyLogFromKey creates a log from an existing private key
func NewTransparencyLogFromKey(priv ed25519.PrivateKey, store *storage.SQLiteStore, malicious bool) (*TransparencyLog, error) {
	publicKey := crypto.PublicKey(priv.Public().(ed25519.PublicKey))
	origin := types.SigsumCheckpointOrigin(&publicKey)

	log := &TransparencyLog{
		privateKey:   priv,
		publicKey:    publicKey,
		origin:       origin,
		leaves:       make([]Leaf, 0),
		treeHeads:    make([]types.TreeHead, 1),
		checkpoints:  make([]*types.Checkpoint, 0),
		store:        store,
		malicious:    malicious,
		altLeaves:    make([]Leaf, 0),
		altTreeHeads: make([]types.TreeHead, 1),
	}

	log.treeHeads[0] = types.NewEmptyTreeHead()
	log.altTreeHeads[0] = types.NewEmptyTreeHead()

	return log, nil
}

// PublicKey returns the log's public key
func (l *TransparencyLog) PublicKey() crypto.PublicKey {
	return l.publicKey
}

// Origin returns the log's origin
func (l *TransparencyLog) Origin() string {
	return l.origin
}

// Size returns the current tree size
func (l *TransparencyLog) Size() uint64 {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return uint64(len(l.leaves))
}

// RootHash returns the current root hash
func (l *TransparencyLog) RootHash() crypto.Hash {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if len(l.treeHeads) > 0 {
		return l.treeHeads[len(l.treeHeads)-1].RootHash
	}
	return merkle.HashEmptyTree()
}

// AddLeaf adds a new leaf to the log
func (l *TransparencyLog) AddLeaf(ctx context.Context, req requests.Leaf, submitHeader *requests.SubmitHeader) (bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Verify the leaf signature
	submitterPubKey, err := crypto.PublicKeyFromBytes(req.KeyHash[:])
	if err != nil {
		return false, fmt.Errorf("invalid submitter key: %w", err)
	}

	leaf := Leaf{
		Checksum:  req.Checksum,
		Signature: req.Signature,
		KeyHash:   req.KeyHash,
	}

	if !submitterPubKey.Verify(leaf.Checksum[:], &leaf.Signature) {
		return false, errors.New("invalid leaf signature")
	}

	l.leaves = append(l.leaves, leaf)
	l.updateTreeHeads()

	return true, nil
}

// GetLeaves returns a range of leaves
func (l *TransparencyLog) GetLeaves(ctx context.Context, req requests.Leaves) ([]types.Leaf, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if req.StartIndex >= uint64(len(l.leaves)) {
		return nil, errors.New("start index out of range")
	}

	end := req.EndIndex
	if end > uint64(len(l.leaves)) {
		end = uint64(len(l.leaves))
	}

	result := make([]types.Leaf, end-req.StartIndex)
	for i := req.StartIndex; i < end; i++ {
		leaf := l.leaves[i]
		result[i-req.StartIndex] = types.Leaf{
			Checksum:  leaf.Checksum,
			Signature: leaf.Signature,
			KeyHash:   leaf.KeyHash,
		}
	}

	return result, nil
}

// GetTreeHead returns the current cosigned tree head
func (l *TransparencyLog) GetTreeHead(ctx context.Context) (types.CosignedTreeHead, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	latestTreeHead := l.treeHeads[len(l.treeHeads)-1]

	// Sign the checkpoint
	signedTreeHead, err := latestTreeHead.Sign(l.privateKey)
	if err != nil {
		return types.CosignedTreeHead{}, fmt.Errorf("failed to sign tree head: %w", err)
	}

	// Create checkpoint
	cp := &checkpoint.Checkpoint{
		SignedTreeHead: signedTreeHead,
		Origin:         l.origin,
		KeyId:          checkpoint.NewLogKeyId(l.origin, &l.publicKey),
	}

	cth := types.CosignedTreeHead{
		SignedTreeHead: signedTreeHead,
		Cosignatures:   make(map[crypto.Hash]types.Cosignature),
	}

	return cth, nil
}

// GetInclusionProof returns an inclusion proof for a leaf
func (l *TransparencyLog) GetInclusionProof(ctx context.Context, req requests.InclusionProof) (types.InclusionProof, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if req.Size > uint64(len(l.leaves)) {
		return types.InclusionProof{}, errors.New("tree size exceeds current size")
	}

	if req.Size < 2 {
		return types.InclusionProof{}, nil
	}

	// Find the leaf index
	leafIndex := -1
	for i := 0; i < len(l.leaves); i++ {
		if l.leaves[i].Checksum == req.LeafHash {
			leafIndex = i
			break
		}
	}

	if leafIndex == -1 {
		return types.InclusionProof{}, errors.New("leaf not found")
	}

	// Generate inclusion proof using RFC 6962 algorithm
	proof := l.generateInclusionProof(uint64(leafIndex), req.Size)
	return proof, nil
}

// GetConsistencyProof returns a consistency proof between two tree sizes
func (l *TransparencyLog) GetConsistencyProof(ctx context.Context, req requests.ConsistencyProof) (types.ConsistencyProof, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if req.OldSize > req.NewSize {
		return types.ConsistencyProof{}, errors.New("old size cannot exceed new size")
	}

	if req.NewSize > uint64(len(l.leaves)) {
		return types.ConsistencyProof{}, errors.New("new size exceeds current size")
	}

	proof := l.generateConsistencyProof(req.OldSize, req.NewSize)
	return proof, nil
}

// generateInclusionProof generates an RFC 6962 inclusion proof
func (l *TransparencyLog) generateInclusionProof(leafIndex, treeSize uint64) types.InclusionProof {
	// Simplified inclusion proof generation
	// In a real implementation, this would compute the Merkle audit path
	var hashes []crypto.Hash

	// This is a placeholder - real implementation would compute the actual proof
	// using the Merkle tree structure
	return types.InclusionProof{
		LeafIndex: leafIndex,
		TreeSize:  treeSize,
		Hashes:    hashes,
	}
}

// generateConsistencyProof generates an RFC 6962 consistency proof
func (l *TransparencyLog) generateConsistencyProof(oldSize, newSize uint64) types.ConsistencyProof {
	// Simplified consistency proof generation
	// Real implementation would compute the actual proof
	var hashes []crypto.Hash

	return types.ConsistencyProof{
		OldSize: oldSize,
		NewSize: newSize,
		Hashes:  hashes,
	}
}

// updateTreeHeads recomputes the Merkle tree heads
func (l *TransparencyLog) updateTreeHeads() {
	// Recompute tree heads for all sizes
	l.treeHeads = make([]types.TreeHead, len(l.leaves)+1)
	l.treeHeads[0] = types.NewEmptyTreeHead()

	for i := 1; i <= len(l.leaves); i++ {
		// Compute root hash for tree of size i
		// This is a simplified implementation
		rootHash := l.computeRootHash(i)
		l.treeHeads[i] = types.TreeHead{
			Size:     uint64(i),
			RootHash: rootHash,
		}
	}
}

// computeRootHash computes the Merkle root for a given tree size
func (l *TransparencyLog) computeRootHash(size int) crypto.Hash {
	if size == 0 {
		return merkle.HashEmptyTree()
	}

	// Build the tree bottom-up
	// This is a simplified implementation
	hashes := make([]crypto.Hash, size)
	for i := 0; i < size; i++ {
		leaf := l.leaves[i]
		hashes[i] = merkle.HashLeafNode(leaf.Checksum[:])
	}

	// Build tree
	for len(hashes) > 1 {
		var next []crypto.Hash
		for i := 0; i < len(hashes); i += 2 {
			if i+1 < len(hashes) {
				next = append(next, merkle.HashInteriorNode(&hashes[i], &hashes[i+1]))
			} else {
				next = append(next, hashes[i])
			}
		}
		hashes = next
	}

	return hashes[0]
}

// CreateCheckpoint creates a signed checkpoint
func (l *TransparencyLog) CreateCheckpoint() (*types.Checkpoint, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	latestTreeHead := l.treeHeads[len(l.treeHeads)-1]
	signedTreeHead, err := latestTreeHead.Sign(l.privateKey)
	if err != nil {
		return nil, err
	}

	cp := &checkpoint.Checkpoint{
		SignedTreeHead: signedTreeHead,
		Origin:         l.origin,
		KeyId:          checkpoint.NewLogKeyId(l.origin, &l.publicKey),
	}

	wrapped := &types.Checkpoint{
		Checkpoint: cp,
		LogID:      l.publicKey.Hash(),
		ReceivedAt: time.Now(),
		Source:     "log",
	}

	l.checkpoints = append(l.checkpoints, wrapped)

	// Save to storage
	if l.store != nil {
		l.store.SaveCheckpoint(wrapped)
	}

	return wrapped, nil
}

// GetCheckpoint returns the latest checkpoint
func (l *TransparencyLog) GetCheckpoint() *types.Checkpoint {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if len(l.checkpoints) > 0 {
		return l.checkpoints[len(l.checkpoints)-1]
	}
	return nil
}

// SetMalicious enables/disables malicious mode
func (l *TransparencyLog) SetMalicious(malicious bool) {
	l.maliciousMu.Lock()
	defer l.maliciousMu.Unlock()
	l.malicious = malicious
}

// IsMalicious returns whether the log is in malicious mode
func (l *TransparencyLog) IsMalicious() bool {
	l.maliciousMu.Lock()
	defer l.maliciousMu.Unlock()
	return l.malicious
}

// CreateAlternativeHistory creates an alternative history for split-view attack
func (l *TransparencyLog) CreateAlternativeHistory(leaves []Leaf) {
	l.maliciousMu.Lock()
	defer l.maliciousMu.Unlock()

	l.altLeaves = make([]Leaf, len(leaves))
	copy(l.altLeaves, leaves)

	// Recompute alt tree heads
	l.altTreeHeads = make([]types.TreeHead, len(leaves)+1)
	l.altTreeHeads[0] = types.NewEmptyTreeHead()

	for i := 1; i <= len(leaves); i++ {
		rootHash := l.computeAltRootHash(i)
		l.altTreeHeads[i] = types.TreeHead{
			Size:     uint64(i),
			RootHash: rootHash,
		}
	}
}

// computeAltRootHash computes root hash for alternative history
func (l *TransparencyLog) computeAltRootHash(size int) crypto.Hash {
	if size == 0 {
		return merkle.HashEmptyTree()
	}

	hashes := make([]crypto.Hash, size)
	for i := 0; i < size; i++ {
		leaf := l.altLeaves[i]
		hashes[i] = merkle.HashLeafNode(leaf.Checksum[:])
	}

	for len(hashes) > 1 {
		var next []crypto.Hash
		for i := 0; i < len(hashes); i += 2 {
			if i+1 < len(hashes) {
				next = append(next, merkle.HashInteriorNode(&hashes[i], &hashes[i+1]))
			} else {
				next = append(next, hashes[i])
			}
		}
		hashes = next
	}

	return hashes[0]
}

// GetMaliciousCheckpoint returns a checkpoint from the alternative history
func (l *TransparencyLog) GetMaliciousCheckpoint(size uint64) (*types.Checkpoint, error) {
	l.maliciousMu.Lock()
	defer l.maliciousMu.Unlock()

	if !l.malicious {
		return nil, errors.New("log not in malicious mode")
	}

	if size > uint64(len(l.altLeaves)) {
		return nil, errors.New("size exceeds alternative history")
	}

	treeHead := l.altTreeHeads[size]
	signedTreeHead, err := treeHead.Sign(l.privateKey)
	if err != nil {
		return nil, err
	}

	cp := &checkpoint.Checkpoint{
		SignedTreeHead: signedTreeHead,
		Origin:         l.origin,
		KeyId:          checkpoint.NewLogKeyId(l.origin, &l.publicKey),
	}

	return &types.Checkpoint{
		Checkpoint: cp,
		LogID:      l.publicKey.Hash(),
		ReceivedAt: time.Now(),
		Source:     "log-malicious",
	}, nil
}

// HTTPHandler returns an HTTP handler for the log
func (l *TransparencyLog) HTTPHandler() http.Handler {
	// Create a custom config
	config := &server.Config{
		UserAgent: "WitnessMesh-Log",
	}

	return server.NewLog(config, l)
}

// Implement api.Log interface
var _ api.Log = (*TransparencyLog)(nil)

// Helper functions for converting between types
func convertLeaves(leaves []Leaf) []types.Leaf {
	result := make([]types.Leaf, len(leaves))
	for i, leaf := range leaves {
		result[i] = types.Leaf{
			Checksum:  leaf.Checksum,
			Signature: leaf.Signature,
			KeyHash:   leaf.KeyHash,
		}
	}
	return result
}

// WriteCheckpoint writes a checkpoint in the tlog-checkpoint format
func WriteCheckpoint(w io.Writer, cp *types.Checkpoint) error {
	return cp.Checkpoint.ToASCII(w)
}

// ParseCheckpoint parses a checkpoint from the tlog-checkpoint format
func ParseCheckpoint(r io.Reader) (*types.Checkpoint, error) {
	cp := &checkpoint.Checkpoint{}
	if err := cp.FromASCII(r); err != nil {
		return nil, err
	}
	return &types.Checkpoint{
		Checkpoint: cp,
		ReceivedAt: time.Now(),
	}, nil
}

// VerifyCheckpoint verifies a checkpoint signature
func VerifyCheckpoint(cp *types.Checkpoint, pubKey *crypto.PublicKey) error {
	return cp.Checkpoint.Verify(pubKey)
}

// KeyIDFromPublicKey derives a key ID for a log
func KeyIDFromPublicKey(origin string, pubKey *crypto.PublicKey) [4]byte {
	return checkpoint.NewLogKeyId(origin, pubKey)
}