// Package verifier implements a standalone offline verifier for evidence bundles.
// It independently validates all cryptographic claims without trusting any metadata.
package verifier

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"sigsum.org/sigsum-go/pkg/checkpoint"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/merkle"

	"witnessmesh/internal/evidence"
	"witnessmesh/internal/types"
)

// VerificationResult represents the result of evidence verification.
// Valid=true means cryptographic evidence establishes the stated inconsistency.
// Valid=false means malformed, forged, inconsistent, or insufficient evidence.
type VerificationResult struct {
	Valid       bool
	Case        types.EvidenceCase
	Description string
	Errors      []string
}

// Verifier is a standalone offline verifier for evidence bundles.
// It has no dependencies on monitoring services or databases.
type Verifier struct {
	// TrustedLogKeys maps log key hashes to their public keys.
	// The verifier ONLY trusts these keys for log signature verification.
	TrustedLogKeys map[crypto.Hash]*crypto.PublicKey

	// TrustedWitnessKeys maps witness key hashes to their public keys.
	// The verifier ONLY trusts these keys for witness cosignature verification.
	TrustedWitnessKeys map[crypto.Hash]*crypto.PublicKey
}

// NewVerifier creates a new standalone verifier.
// The verifier starts with no trusted keys - they must be configured before use.
func NewVerifier() *Verifier {
	return &Verifier{
		TrustedLogKeys:     make(map[crypto.Hash]*crypto.PublicKey),
		TrustedWitnessKeys: make(map[crypto.Hash]*crypto.PublicKey),
	}
}

// AddTrustedLogKey adds a trusted log public key.
// The verifier will only accept checkpoints signed by trusted log keys.
func (v *Verifier) AddTrustedLogKey(pubKey *crypto.PublicKey) {
	keyHash := pubKey.Hash()
	v.TrustedLogKeys[keyHash] = pubKey
}

// AddTrustedWitnessKey adds a trusted witness public key.
// The verifier will only accept cosignatures from trusted witness keys.
func (v *Verifier) AddTrustedWitnessKey(pubKey *crypto.PublicKey) {
	keyHash := pubKey.Hash()
	v.TrustedWitnessKeys[keyHash] = pubKey
}

// VerifyFile reads an evidence bundle from a file and verifies it.
// Supports both JSON and deterministic binary (hex-encoded) formats.
func (v *Verifier) VerifyFile(filename string) (*VerificationResult, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}
	return v.VerifyBytes(data)
}

// VerifyBytes verifies an evidence bundle from raw bytes.
// Automatically detects JSON or deterministic binary format.
func (v *Verifier) VerifyBytes(data []byte) (*VerificationResult, error) {
	// Try JSON first
	var eb evidence.EvidenceBundle
	if err := json.Unmarshal(data, &eb); err == nil {
		return v.VerifyBundle(&eb), nil
	}

	// Try hex-encoded deterministic binary
	decoded, err := hex.DecodeString(string(data))
	if err == nil {
		ebPtr, err := evidence.DeserializeDeterministic(decoded)
		if err == nil {
			return v.VerifyBundle(ebPtr), nil
		}
	}

	// Try raw deterministic binary
	ebPtr, err := evidence.DeserializeDeterministic(data)
	if err == nil {
		return v.VerifyBundle(ebPtr), nil
	}

	return &VerificationResult{
		Valid:  false,
		Errors: []string{"malformed serialization: unable to parse as JSON or deterministic binary"},
	}, nil
}

// VerifyBundle performs complete cryptographic verification of an evidence bundle.
// This is the core verification logic - it does NOT trust any metadata conclusions.
func (v *Verifier) VerifyBundle(eb *evidence.EvidenceBundle) *VerificationResult {
	result := &VerificationResult{
		Valid:  true,
		Case:   eb.Case,
		Errors: nil,
	}

	// 1. Check format version
	if eb.FormatVersion != evidence.EvidenceFormatVersion {
		result.Valid = false
		result.Errors = append(result.Errors,
			fmt.Sprintf("unsupported evidence version: %d (expected %d)", eb.FormatVersion, evidence.EvidenceFormatVersion))
		return result
	}

	// 2. Verify log identity is trusted
	logKeyHash := eb.LogIdentity.PublicKey.Hash()
	logPubKey, ok := v.TrustedLogKeys[logKeyHash]
	if !ok {
		result.Valid = false
		result.Errors = append(result.Errors,
			fmt.Sprintf("log identity not trusted: key hash %x", logKeyHash[:4]))
		return result
	}

	// Verify log identity public key matches trusted key
	if eb.LogIdentity.PublicKey != *logPubKey {
		result.Valid = false
		result.Errors = append(result.Errors, "log identity public key mismatch")
		return result
	}

	// 3. Verify all checkpoint signatures
	for i, cp := range eb.Checkpoints {
		if err := v.verifyCheckpointSignature(cp, logPubKey); err != nil {
			result.Valid = false
			result.Errors = append(result.Errors,
				fmt.Sprintf("checkpoint %d: invalid log signature: %v", i, err))
		}
		// Verify checkpoint log ID matches log identity
		if cp.LogID != logKeyHash {
			result.Valid = false
			result.Errors = append(result.Errors,
				fmt.Sprintf("checkpoint %d: log ID mismatch (expected %x, got %x)", i, logKeyHash[:4], cp.LogID[:4]))
		}
	}

	if !result.Valid {
		return result
	}

	// 4. Case-specific verification
	switch eb.Case {
	case types.EvidenceCaseSameSizeFork:
		result.Description = "Same-size fork: two checkpoints with same log ID and size, different roots"
		v.verifySameSizeFork(eb, result)

	case types.EvidenceCaseDifferentSizeFork:
		result.Description = "Different-size fork: two checkpoints at different sizes with consistency proof"
		v.verifyDifferentSizeFork(eb, result)

	case types.EvidenceCaseWitnessEquivocation:
		result.Description = "Witness equivocation: single witness signing conflicting checkpoints"
		v.verifyWitnessEquivocation(eb, result)

	default:
		result.Valid = false
		result.Errors = append(result.Errors,
			fmt.Sprintf("unknown evidence case: %d", eb.Case))
	}

	return result
}

// verifyCheckpointSignature verifies a checkpoint's log signature.
func (v *Verifier) verifyCheckpointSignature(cp *types.Checkpoint, logPubKey *crypto.PublicKey) error {
	// The checkpoint must have a valid signature from the log's private key
	return cp.Checkpoint.Verify(logPubKey)
}

// verifySameSizeFork verifies evidence for a same-size fork.
// Requires: 2 checkpoints, same log ID, same tree size, different root hashes, both with valid log signatures.
func (v *Verifier) verifySameSizeFork(eb *evidence.EvidenceBundle, result *VerificationResult) {
	if len(eb.Checkpoints) != 2 {
		result.Valid = false
		result.Errors = append(result.Errors, "same-size fork requires exactly 2 checkpoints")
		return
	}

	cp1, cp2 := eb.Checkpoints[0], eb.Checkpoints[1]

	// Check same tree size
	if cp1.Checkpoint.SignedTreeHead.Size != cp2.Checkpoint.SignedTreeHead.Size {
		result.Valid = false
		result.Errors = append(result.Errors,
			fmt.Sprintf("checkpoints have different tree sizes: %d vs %d",
				cp1.Checkpoint.SignedTreeHead.Size, cp2.Checkpoint.SignedTreeHead.Size))
		return
	}

	// Check different root hashes (this IS the fork)
	if cp1.Checkpoint.SignedTreeHead.RootHash == cp2.Checkpoint.SignedTreeHead.RootHash {
		result.Valid = false
		result.Errors = append(result.Errors, "checkpoints have same root hash (not a fork)")
		return
	}

	// Check same log ID
	if cp1.LogID != cp2.LogID {
		result.Valid = false
		result.Errors = append(result.Errors, "checkpoints have different log IDs")
		return
	}

	// Both signatures already verified above
	result.Description = fmt.Sprintf("Same-size fork at tree size %d: root hashes %x vs %x",
		cp1.Checkpoint.SignedTreeHead.Size,
		cp1.Checkpoint.SignedTreeHead.RootHash[:4],
		cp2.Checkpoint.SignedTreeHead.RootHash[:4])
}

// verifyDifferentSizeFork verifies evidence for a different-size fork.
// Requires: 2 checkpoints at different sizes, valid consistency proof, tree data to verify it.
func (v *Verifier) verifyDifferentSizeFork(eb *evidence.EvidenceBundle, result *VerificationResult) {
	if len(eb.Checkpoints) != 2 {
		result.Valid = false
		result.Errors = append(result.Errors, "different-size fork requires exactly 2 checkpoints")
		return
	}

	cpOld, cpNew := eb.Checkpoints[0], eb.Checkpoints[1]

	// Check same log ID
	if cpOld.LogID != cpNew.LogID {
		result.Valid = false
		result.Errors = append(result.Errors, "checkpoints have different log IDs")
		return
	}

	// Check size ordering
	if cpOld.Checkpoint.SignedTreeHead.Size >= cpNew.Checkpoint.SignedTreeHead.Size {
		result.Valid = false
		result.Errors = append(result.Errors,
			fmt.Sprintf("old checkpoint size (%d) not less than new (%d)",
				cpOld.Checkpoint.SignedTreeHead.Size, cpNew.Checkpoint.SignedTreeHead.Size))
		return
	}

	// Check consistency proof exists
	if eb.ConsistencyProof == nil {
		result.Valid = false
		result.Errors = append(result.Errors, "missing consistency proof")
		return
	}

	// Verify consistency proof parameters match checkpoints
	if eb.ConsistencyProof.OldSize != cpOld.Checkpoint.SignedTreeHead.Size {
		result.Valid = false
		result.Errors = append(result.Errors,
			fmt.Sprintf("consistency proof old size (%d) != old checkpoint size (%d)",
				eb.ConsistencyProof.OldSize, cpOld.Checkpoint.SignedTreeHead.Size))
		return
	}
	if eb.ConsistencyProof.NewSize != cpNew.Checkpoint.SignedTreeHead.Size {
		result.Valid = false
		result.Errors = append(result.Errors,
			fmt.Sprintf("consistency proof new size (%d) != new checkpoint size (%d)",
				eb.ConsistencyProof.NewSize, cpNew.Checkpoint.SignedTreeHead.Size))
		return
	}

	// Verify consistency proof using tree data
	if eb.TreeData == nil {
		result.Valid = false
		result.Errors = append(result.Errors, "missing tree data required for consistency proof verification")
		return
	}

	if err := v.verifyConsistencyProof(eb.ConsistencyProof, eb.TreeData, cpOld, cpNew); err != nil {
		result.Valid = false
		result.Errors = append(result.Errors,
			fmt.Sprintf("consistency proof verification failed: %v", err))
		return
	}

	result.Description = fmt.Sprintf("Different-size fork: size %d -> %d",
		cpOld.Checkpoint.SignedTreeHead.Size, cpNew.Checkpoint.SignedTreeHead.Size)
}

// verifyConsistencyProof verifies a Merkle consistency proof per RFC 6962.
// This is the critical cryptographic check - it MUST verify the proof independently.
func (v *Verifier) verifyConsistencyProof(proof *evidence.ConsistencyProof, treeData *evidence.TreeData, cpOld, cpNew *types.Checkpoint) error {
	// We need the leaves at old size to verify the proof
	if len(treeData.Leaves) == 0 {
		return errors.New("no leaf hashes provided for consistency proof verification")
	}

	// Verify leaf count matches old size
	if uint64(len(treeData.Leaves)) != proof.OldSize {
		return fmt.Errorf("leaf count (%d) does not match old size (%d)",
			len(treeData.Leaves), proof.OldSize)
	}

	// Compute old root from leaves
	computedOldRoot := computeRootHash(treeData.Leaves)
	if computedOldRoot != cpOld.Checkpoint.SignedTreeHead.RootHash {
		return fmt.Errorf("computed old root %x does not match checkpoint root %x",
			computedOldRoot[:4], cpOld.Checkpoint.SignedTreeHead.RootHash[:4])
	}

	// Verify consistency proof using sigsum-go merkle.VerifyConsistency
	// This verifies that the new root can be computed from the old root and proof hashes
	err := merkle.VerifyConsistency(
		proof.OldSize,
		proof.NewSize,
		&cpOld.Checkpoint.SignedTreeHead.RootHash,
		&cpNew.Checkpoint.SignedTreeHead.RootHash,
		proof.Hashes,
	)
	if err != nil {
		return fmt.Errorf("consistency proof verification failed: %w", err)
	}

	return nil
}

// verifyWitnessEquivocation verifies evidence for witness equivocation.
// Requires: 2 checkpoints, 2+ cosignatures from SAME witness on DIFFERENT checkpoints.
func (v *Verifier) verifyWitnessEquivocation(eb *evidence.EvidenceBundle, result *VerificationResult) {
	if len(eb.Checkpoints) != 2 {
		result.Valid = false
		result.Errors = append(result.Errors, "witness equivocation requires exactly 2 checkpoints")
		return
	}

	if len(eb.Cosignatures) < 2 {
		result.Valid = false
		result.Errors = append(result.Errors, "witness equivocation requires at least 2 cosignatures")
		return
	}

	// All cosignatures must be from the same witness
	witnessHash := eb.Cosignatures[0].WitnessID
	witnessPubKey, ok := v.TrustedWitnessKeys[witnessHash]
	if !ok {
		result.Valid = false
		result.Errors = append(result.Errors,
			fmt.Sprintf("witness public key not trusted: %x", witnessHash[:4]))
		return
	}

	for i, cosig := range eb.Cosignatures {
		// Check all cosignatures from same witness
		if cosig.WitnessID != witnessHash {
			result.Valid = false
			result.Errors = append(result.Errors,
				fmt.Sprintf("cosignature %d from different witness (expected %x, got %x)",
					i, witnessHash[:4], cosig.WitnessID[:4]))
			continue
		}

		// Find matching checkpoint
		var matchedCP *types.Checkpoint
		for _, cp := range eb.Checkpoints {
			if cp.Checkpoint.SignedTreeHead.Size == cosig.TreeSize &&
				cp.Checkpoint.SignedTreeHead.RootHash == cosig.RootHash {
				matchedCP = cp
				break
			}
		}
		if matchedCP == nil {
			result.Valid = false
			result.Errors = append(result.Errors,
				fmt.Sprintf("cosignature %d does not match any checkpoint", i))
			continue
		}

		// Verify the cosignature
		if !matchedCP.Checkpoint.VerifyCosignature(witnessPubKey, &cosig.Cosignature) {
			result.Valid = false
			result.Errors = append(result.Errors,
				fmt.Sprintf("cosignature %d verification failed", i))
		}
	}

	// Verify checkpoints are conflicting (different log ID, size, or root)
	cp1, cp2 := eb.Checkpoints[0], eb.Checkpoints[1]
	sameLogID := cp1.LogID == cp2.LogID
	sameSize := cp1.Checkpoint.SignedTreeHead.Size == cp2.Checkpoint.SignedTreeHead.Size
	sameRoot := cp1.Checkpoint.SignedTreeHead.RootHash == cp2.Checkpoint.SignedTreeHead.RootHash

	if sameLogID && sameSize && sameRoot {
		result.Valid = false
		result.Errors = append(result.Errors, "checkpoints are not conflicting (same log ID, size, and root)")
	}
}

// VerifyCheckpointSignature is a helper to verify a single checkpoint signature.
// Useful for standalone checkpoint verification.
func (v *Verifier) VerifyCheckpointSignature(cp *types.Checkpoint) error {
	logKeyHash := cp.LogID
	logPubKey, ok := v.TrustedLogKeys[logKeyHash]
	if !ok {
		return fmt.Errorf("log key not trusted: %x", logKeyHash[:4])
	}
	return v.verifyCheckpointSignature(cp, logPubKey)
}

// VerifyCosignature verifies a single witness cosignature.
func (v *Verifier) VerifyCosignature(cp *types.Checkpoint, cosig *types.Cosignature) error {
	witnessPubKey, ok := v.TrustedWitnessKeys[cosig.WitnessID]
	if !ok {
		return fmt.Errorf("witness key not trusted: %x", cosig.WitnessID[:4])
	}
	if !cp.Checkpoint.VerifyCosignature(witnessPubKey, &cosig.Cosignature) {
		return errors.New("cosignature verification failed")
	}
	return nil
}

// VerifyMerkleConsistencyProof is a standalone function to verify a consistency proof
// given the leaf hashes, proof hashes, and expected root hashes.
// Returns nil if valid, error if invalid.
func VerifyMerkleConsistencyProof(
	leaves []crypto.Hash,
	proofHashes []crypto.Hash,
	oldSize, newSize uint64,
	expectedOldRoot, expectedNewRoot crypto.Hash,
) error {
	if uint64(len(leaves)) != oldSize {
		return fmt.Errorf("leaf count (%d) != old size (%d)", len(leaves), oldSize)
	}

	computedOldRoot := computeRootHash(leaves)
	if computedOldRoot != expectedOldRoot {
		return fmt.Errorf("computed old root %x != expected %x", computedOldRoot[:4], expectedOldRoot[:4])
	}

	err := merkle.VerifyConsistency(
		oldSize,
		newSize,
		&expectedOldRoot,
		&expectedNewRoot,
		proofHashes,
	)
	if err != nil {
		return fmt.Errorf("consistency proof verification failed: %w", err)
	}

	return nil
}

// computeRootHash computes the Merkle root hash from leaf hashes per RFC 6962.
// This is a helper function since sigsum-go merkle package doesn't expose ComputeRootHash directly.
func computeRootHash(leaves []crypto.Hash) crypto.Hash {
	tree := merkle.NewTree()
	for _, l := range leaves {
		h := l
		tree.AddLeafHash(&h)
	}
	return tree.GetRootHash()
}

// VerifyMerkleInclusionProof verifies a single inclusion proof.
func VerifyMerkleInclusionProof(leaf *crypto.Hash, leafIndex, treeSize uint64, proofHashes []crypto.Hash, rootHash crypto.Hash) bool {
	if leaf == nil {
		return false
	}
	return merkle.VerifyInclusion(leaf, leafIndex, treeSize, &rootHash, proofHashes) == nil
}

// ParseCheckpointFromASCII parses a checkpoint from ASCII format.
func ParseCheckpointFromASCII(data []byte) (*types.Checkpoint, error) {
	cp := &checkpoint.Checkpoint{}
	if err := cp.FromASCII(bytes.NewReader(data)); err != nil {
		return nil, err
	}
	var logID crypto.Hash
	copy(logID[:4], cp.KeyId[:])
	return &types.Checkpoint{
		Checkpoint: cp,
		LogID:      logID,
	}, nil
}

// ParseEvidenceBundle parses an evidence bundle from JSON or binary format.
func ParseEvidenceBundle(data []byte) (*evidence.EvidenceBundle, error) {
	// Try JSON
	var eb evidence.EvidenceBundle
	if err := json.Unmarshal(data, &eb); err == nil {
		return &eb, nil
	}

	// Try hex-encoded binary
	decoded, err := hex.DecodeString(string(data))
	if err == nil {
		return evidence.DeserializeDeterministic(decoded)
	}

	// Try raw binary
	return evidence.DeserializeDeterministic(data)
}