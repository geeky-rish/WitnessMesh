// Package verifier implements a standalone offline verifier for evidence bundles.
package verifier

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"testing"

	"sigsum.org/sigsum-go/pkg/checkpoint"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/merkle"
	sigsumtypes "sigsum.org/sigsum-go/pkg/types"

	"witnessmesh/internal/evidence"
	"witnessmesh/internal/types"
)

// Test setup helpers

func generateKeyPair(t *testing.T) (ed25519.PrivateKey, crypto.PublicKey) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	return priv, crypto.PublicKey(pub)
}

func createTestLogIdentity(t *testing.T, pubKey crypto.PublicKey) types.LogIdentity {
	origin := types.SigsumCheckpointOrigin(&pubKey)
	return types.LogIdentity{
		PublicKey: pubKey,
		Origin:    origin,
	}
}

func createTestCheckpoint(t *testing.T, logPriv ed25519.PrivateKey, logPubKey crypto.PublicKey, size uint64, leaves []crypto.Hash) *types.Checkpoint {
	var rootHash crypto.Hash
	if size == 0 {
		rootHash = merkle.HashEmptyTree()
	} else {
		rootHash = merkle.ComputeRootHash(leaves[:size])
	}

	treeHead := types.TreeHead{
		Size:     size,
		RootHash: rootHash,
	}

	signedTreeHead, err := treeHead.Sign(logPriv)
	if err != nil {
		t.Fatalf("failed to sign tree head: %v", err)
	}

	cp := &checkpoint.Checkpoint{
		SignedTreeHead: signedTreeHead,
		Origin:         types.SigsumCheckpointOrigin(&logPubKey),
		KeyId:          checkpoint.NewLogKeyId(types.SigsumCheckpointOrigin(&logPubKey), &logPubKey),
	}

	return &types.Checkpoint{
		Checkpoint: cp,
		LogID:      logPubKey.Hash(),
		Source:     "test",
	}
}

func createTestLeaves(t *testing.T, count int) []crypto.Hash {
	leaves := make([]crypto.Hash, count)
	for i := 0; i < count; i++ {
		data := []byte{byte(i), byte(i >> 8), byte(i >> 16), byte(i >> 24)}
		// Pad to 32 bytes
		leafData := make([]byte, 32)
		copy(leafData, data)
		leaves[i] = merkle.HashLeafNode(leafData)
	}
	return leaves
}

func setupVerifier(logPubKey, witnessPubKey *crypto.PublicKey) *Verifier {
	v := NewVerifier()
	v.AddTrustedLogKey(logPubKey)
	if witnessPubKey != nil {
		v.AddTrustedWitnessKey(witnessPubKey)
	}
	return v
}

// ============================================================================
// POSITIVE TESTS
// ============================================================================

func TestVerifier_ValidSameSizeFork(t *testing.T) {
	// Generate log keys
	logPriv, logPubKey := generateKeyPair(t)
	logIdentity := createTestLogIdentity(t, logPubKey)

	// Create leaves for tree size 10
	leaves := createTestLeaves(t, 10)

	// Create two checkpoints at same size (10) but with DIFFERENT leaves (fork)
	// First checkpoint: leaves 0-9
	cp1 := createTestCheckpoint(t, logPriv, logPubKey, 10, leaves)

	// Second checkpoint: different leaves at same size (simulating fork)
	altLeaves := createTestLeaves(t, 10)
	// Modify one leaf to create different root
	altLeaves[5] = crypto.Hash{} // Different leaf
	cp2 := createTestCheckpoint(t, logPriv, logPubKey, 10, altLeaves)

	// Verify they have different roots
	if cp1.Checkpoint.SignedTreeHead.RootHash == cp2.Checkpoint.SignedTreeHead.RootHash {
		t.Fatal("checkpoints should have different roots")
	}

	// Create evidence bundle
	eb, err := evidence.CreateSameSizeForkEvidence(logIdentity, cp1, cp2, "test-detector", "test")
	if err != nil {
		t.Fatalf("failed to create evidence: %v", err)
	}

	// Verify
	v := setupVerifier(&logPubKey, nil)
	result := v.VerifyBundle(eb)

	if !result.Valid {
		t.Errorf("expected VALID, got INVALID: %v", result.Errors)
	}
	if result.Case != evidence.EvidenceCaseSameSizeFork {
		t.Errorf("expected case SameSizeFork, got %v", result.Case)
	}
}

func TestVerifier_ValidDifferentSizeFork(t *testing.T) {
	// Generate log keys
	logPriv, logPubKey := generateKeyPair(t)
	logIdentity := createTestLogIdentity(t, logPubKey)

	// Create leaves for tree sizes 5 and 10
	leaves := createTestLeaves(t, 10)

	// Old checkpoint at size 5
	cpOld := createTestCheckpoint(t, logPriv, logPubKey, 5, leaves)

	// New checkpoint at size 10 (extension of old)
	cpNew := createTestCheckpoint(t, logPriv, logPubKey, 10, leaves)

	// Generate consistency proof
	proofHashes := merkle.GenerateConsistencyProof(leaves[:5], 5, 10)
	consistencyProof := evidence.ConsistencyProofFromHashes(5, 10, proofHashes)

	// Tree data with leaves at old size
	treeData := evidence.TreeDataFromLeaves(leaves[:5])

	// Create evidence bundle
	eb, err := evidence.CreateDifferentSizeForkEvidence(logIdentity, cpOld, cpNew, consistencyProof, treeData, "test-detector", "test")
	if err != nil {
		t.Fatalf("failed to create evidence: %v", err)
	}

	// Verify
	v := setupVerifier(&logPubKey, nil)
	result := v.VerifyBundle(eb)

	if !result.Valid {
		t.Errorf("expected VALID, got INVALID: %v", result.Errors)
	}
	if result.Case != evidence.EvidenceCaseDifferentSizeFork {
		t.Errorf("expected case DifferentSizeFork, got %v", result.Case)
	}
}

func TestVerifier_ValidWitnessEquivocation(t *testing.T) {
	// Generate keys
	logPriv, logPubKey := generateKeyPair(t)
	witnessPriv, witnessPubKey := generateKeyPair(t)

	logIdentity := createTestLogIdentity(t, logPubKey)

	// Create leaves
	leaves := createTestLeaves(t, 10)

	// Create two different checkpoints
	cp1 := createTestCheckpoint(t, logPriv, logPubKey, 5, leaves)
	cp2 := createTestCheckpoint(t, logPriv, logPubKey, 10, leaves)

	// Witness signs both checkpoints (equivocation)
	cosig1 := cp1.Checkpoint.SignCosignature(witnessPriv)
	cosig2 := cp2.Checkpoint.SignCosignature(witnessPriv)

	witnessHash := witnessPubKey.Hash()
	cosignatures := []types.Cosignature{
		{
			CosignatureLine: *cosig1,
			WitnessID:       witnessHash,
		},
		{
			CosignatureLine: *cosig2,
			WitnessID:       witnessHash,
		},
	}

	// Create evidence bundle
	eb, err := evidence.CreateWitnessEquivocationEvidence(logIdentity, cp1, cp2, cosignatures, "test-detector", "test")
	if err != nil {
		t.Fatalf("failed to create evidence: %v", err)
	}

	// Verify
	v := setupVerifier(&logPubKey, &witnessPubKey)
	result := v.VerifyBundle(eb)

	if !result.Valid {
		t.Errorf("expected VALID, got INVALID: %v", result.Errors)
	}
	if result.Case != evidence.EvidenceCaseWitnessEquivocation {
		t.Errorf("expected case WitnessEquivocation, got %v", result.Case)
	}
}

// ============================================================================
// NEGATIVE TEST 1: Truncated evidence bundle
// ============================================================================

func TestVerifier_TruncatedEvidenceBundle(t *testing.T) {
	logPriv, logPubKey := generateKeyPair(t)
	logIdentity := createTestLogIdentity(t, logPubKey)
	leaves := createTestLeaves(t, 10)

	cp1 := createTestCheckpoint(t, logPriv, logPubKey, 10, leaves)
	cp2 := createTestCheckpoint(t, logPriv, logPubKey, 10, createTestLeaves(t, 10))

	eb, err := evidence.CreateSameSizeForkEvidence(logIdentity, cp1, cp2, "test", "test")
	if err != nil {
		t.Fatalf("failed to create evidence: %v", err)
	}

	// Serialize to JSON
	data, err := json.Marshal(eb)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	// Truncate the data
	truncated := data[:len(data)/2]

	v := setupVerifier(&logPubKey, nil)
	result := v.VerifyBytes(truncated)

	if result.Valid {
		t.Error("expected INVALID for truncated bundle, got VALID")
	}
	if len(result.Errors) == 0 {
		t.Error("expected errors for truncated bundle")
	}
}

// ============================================================================
// NEGATIVE TEST 2: Invalid log signature
// ============================================================================

func TestVerifier_InvalidLogSignature(t *testing.T) {
	logPriv, logPubKey := generateKeyPair(t)
	_, otherPubKey := generateKeyPair(t) // Different key
	logIdentity := createTestLogIdentity(t, logPubKey)
	leaves := createTestLeaves(t, 10)

	cp1 := createTestCheckpoint(t, logPriv, logPubKey, 10, leaves)
	// Create second checkpoint signed by DIFFERENT key (invalid signature for this log)
	altLeaves := createTestLeaves(t, 10)
	altLeaves[5] = crypto.Hash{}
	cp2 := createTestCheckpoint(t, logPriv, logPubKey, 10, altLeaves)

	// Manually corrupt cp2's signature by using a different key to sign
	otherPriv, _ := generateKeyPair(t)
	treeHead := types.TreeHead{
		Size:     10,
		RootHash: cp2.Checkpoint.SignedTreeHead.RootHash,
	}
	signedTreeHead, err := treeHead.Sign(otherPriv)
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}
	cp2.Checkpoint.SignedTreeHead.Signature = signedTreeHead.Signature

	eb, err := evidence.CreateSameSizeForkEvidence(logIdentity, cp1, cp2, "test", "test")
	if err != nil {
		t.Fatalf("failed to create evidence: %v", err)
	}

	v := setupVerifier(&logPubKey, nil)
	result := v.VerifyBundle(eb)

	if result.Valid {
		t.Error("expected INVALID for invalid log signature, got VALID")
	}
	found := false
	for _, e := range result.Errors {
		if contains(e, "signature") || contains(e, "invalid") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected signature error, got: %v", result.Errors)
	}
}

// ============================================================================
// NEGATIVE TEST 3: Invalid witness signature
// ============================================================================

func TestVerifier_InvalidWitnessSignature(t *testing.T) {
	logPriv, logPubKey := generateKeyPair(t)
	witnessPriv, witnessPubKey := generateKeyPair(t)
	_, otherWitnessPubKey := generateKeyPair(t)

	logIdentity := createTestLogIdentity(t, logPubKey)
	leaves := createTestLeaves(t, 10)

	cp1 := createTestCheckpoint(t, logPriv, logPubKey, 5, leaves)
	cp2 := createTestCheckpoint(t, logPriv, logPubKey, 10, leaves)

	// Valid cosignature from witness
	cosig1 := cp1.Checkpoint.SignCosignature(witnessPriv)

	// Invalid cosignature: signed by different witness key
	otherWitnessPriv, _ := generateKeyPair(t)
	cosig2 := cp2.Checkpoint.SignCosignature(otherWitnessPriv)

	witnessHash := witnessPubKey.Hash()
	cosignatures := []types.Cosignature{
		{CosignatureLine: *cosig1, WitnessID: witnessHash},
		{CosignatureLine: *cosig2, WitnessID: witnessHash}, // Claims to be from same witness but isn't
	}

	eb, err := evidence.CreateWitnessEquivocationEvidence(logIdentity, cp1, cp2, cosignatures, "test", "test")
	if err != nil {
		t.Fatalf("failed to create evidence: %v", err)
	}

	v := setupVerifier(&logPubKey, &witnessPubKey)
	result := v.VerifyBundle(eb)

	if result.Valid {
		t.Error("expected INVALID for invalid witness signature, got VALID")
	}
	found := false
	for _, e := range result.Errors {
		if contains(e, "cosignature") || contains(e, "verification failed") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected cosignature error, got: %v", result.Errors)
	}
}

// ============================================================================
// NEGATIVE TEST 4: Mismatched log identity
// ============================================================================

func TestVerifier_MismatchedLogIdentity(t *testing.T) {
	logPriv, logPubKey := generateKeyPair(t)
	_, otherLogPubKey := generateKeyPair(t)

	// Evidence claims to be from logPubKey but checkpoints signed by otherLogPubKey
	logIdentity := createTestLogIdentity(t, logPubKey)
	leaves := createTestLeaves(t, 10)

	// Create checkpoints signed by OTHER log key
	cp1 := createTestCheckpoint(t, logPriv, logPubKey, 10, leaves)
	altLeaves := createTestLeaves(t, 10)
	altLeaves[5] = crypto.Hash{}
	cp2 := createTestCheckpoint(t, logPriv, logPubKey, 10, altLeaves)

	// Corrupt log IDs in checkpoints to mismatch
	cp1.LogID = otherLogPubKey.Hash()
	cp2.LogID = otherLogPubKey.Hash()

	eb, err := evidence.CreateSameSizeForkEvidence(logIdentity, cp1, cp2, "test", "test")
	if err != nil {
		t.Fatalf("failed to create evidence: %v", err)
	}

	v := setupVerifier(&logPubKey, nil)
	result := v.VerifyBundle(eb)

	if result.Valid {
		t.Error("expected INVALID for mismatched log identity, got VALID")
	}
	found := false
	for _, e := range result.Errors {
		if contains(e, "log ID") || contains(e, "mismatch") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected log ID mismatch error, got: %v", result.Errors)
	}
}

// ============================================================================
// NEGATIVE TEST 5: Incorrect tree size
// ============================================================================

func TestVerifier_IncorrectTreeSize(t *testing.T) {
	logPriv, logPubKey := generateKeyPair(t)
	logIdentity := createTestLogIdentity(t, logPubKey)
	leaves := createTestLeaves(t, 10)

	// Create checkpoint at size 10
	cp1 := createTestCheckpoint(t, logPriv, logPubKey, 10, leaves)

	// Create checkpoint at size 5 but claim it's size 10 (incorrect tree size)
	cp2 := createTestCheckpoint(t, logPriv, logPubKey, 5, leaves)
	// Manually change the size in signed tree head to 10 (mismatch with actual leaves)
	cp2.Checkpoint.SignedTreeHead.Size = 10
	// Re-sign with correct key but wrong size
	treeHead := types.TreeHead{
		Size:     10,
		RootHash: cp2.Checkpoint.SignedTreeHead.RootHash,
	}
	signedTreeHead, err := treeHead.Sign(logPriv)
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}
	cp2.Checkpoint.SignedTreeHead = signedTreeHead

	eb, err := evidence.CreateSameSizeForkEvidence(logIdentity, cp1, cp2, "test", "test")
	if err != nil {
		t.Fatalf("failed to create evidence: %v", err)
	}

	v := setupVerifier(&logPubKey, nil)
	result := v.VerifyBundle(eb)

	if result.Valid {
		t.Error("expected INVALID for incorrect tree size, got VALID")
	}
	found := false
	for _, e := range result.Errors {
		if contains(e, "size") || contains(e, "different") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected tree size error, got: %v", result.Errors)
	}
}

// ============================================================================
// NEGATIVE TEST 6: Invalid Merkle consistency proof
// ============================================================================

func TestVerifier_InvalidMerkleConsistencyProof(t *testing.T) {
	logPriv, logPubKey := generateKeyPair(t)
	logIdentity := createTestLogIdentity(t, logPubKey)
	leaves := createTestLeaves(t, 10)

	cpOld := createTestCheckpoint(t, logPriv, logPubKey, 5, leaves)
	cpNew := createTestCheckpoint(t, logPriv, logPubKey, 10, leaves)

	// Generate INVALID consistency proof (wrong hashes)
	proofHashes := []crypto.Hash{crypto.Hash{1, 2, 3, 4}} // Random hashes
	consistencyProof := evidence.ConsistencyProofFromHashes(5, 10, proofHashes)
	treeData := evidence.TreeDataFromLeaves(leaves[:5])

	eb, err := evidence.CreateDifferentSizeForkEvidence(logIdentity, cpOld, cpNew, consistencyProof, treeData, "test", "test")
	if err != nil {
		t.Fatalf("failed to create evidence: %v", err)
	}

	v := setupVerifier(&logPubKey, nil)
	result := v.VerifyBundle(eb)

	if result.Valid {
		t.Error("expected INVALID for invalid consistency proof, got VALID")
	}
	found := false
	for _, e := range result.Errors {
		if contains(e, "consistency proof") || contains(e, "verification failed") || contains(e, "yield") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected consistency proof error, got: %v", result.Errors)
	}
}

// ============================================================================
// NEGATIVE TEST 7: Altered Merkle root
// ============================================================================

func TestVerifier_AlteredMerkleRoot(t *testing.T) {
	logPriv, logPubKey := generateKeyPair(t)
	logIdentity := createTestLogIdentity(t, logPubKey)
	leaves := createTestLeaves(t, 10)

	cp1 := createTestCheckpoint(t, logPriv, logPubKey, 10, leaves)
	cp2 := createTestCheckpoint(t, logPriv, logPubKey, 10, leaves)

	// Alter the root hash in cp2 (but keep valid signature - this simulates a forged checkpoint)
	cp2.Checkpoint.SignedTreeHead.RootHash = crypto.Hash{0xff, 0xff, 0xff, 0xff}

	// Note: The signature is now invalid for this root, but the evidence builder will fail
	// Let's create evidence manually with valid signatures but altered root
	// Actually, the evidence builder verifies signatures, so we need to bypass that
	// We'll create the evidence bundle directly

	eb := &evidence.EvidenceBundle{
		FormatVersion: evidence.EvidenceFormatVersion,
		LogIdentity:   logIdentity,
		Case:          evidence.EvidenceCaseSameSizeFork,
		Checkpoints:   []*types.Checkpoint{cp1, cp2},
		CreatedAt:     *new(bytes.Buffer), // placeholder
	}

	// Manually set valid signatures for cp2 with altered root
	treeHead := types.TreeHead{
		Size:     10,
		RootHash: cp2.Checkpoint.SignedTreeHead.RootHash, // Altered root
	}
	signedTreeHead, err := treeHead.Sign(logPriv)
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}
	cp2.Checkpoint.SignedTreeHead = signedTreeHead

	v := setupVerifier(&logPubKey, nil)
	result := v.VerifyBundle(eb)

	if result.Valid {
		t.Error("expected INVALID for altered Merkle root, got VALID")
	}
	found := false
	for _, e := range result.Errors {
		if contains(e, "root") || contains(e, "fork") || contains(e, "different") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected root hash error, got: %v", result.Errors)
	}
}

// ============================================================================
// NEGATIVE TEST 8: Missing required signature
// ============================================================================

func TestVerifier_MissingRequiredSignature(t *testing.T) {
	logPriv, logPubKey := generateKeyPair(t)
	witnessPriv, witnessPubKey := generateKeyPair(t)

	logIdentity := createTestLogIdentity(t, logPubKey)
	leaves := createTestLeaves(t, 10)

	cp1 := createTestCheckpoint(t, logPriv, logPubKey, 5, leaves)
	cp2 := createTestCheckpoint(t, logPriv, logPubKey, 10, leaves)

	// Only ONE cosignature (need at least 2 for witness equivocation)
	cosig1 := cp1.Checkpoint.SignCosignature(witnessPriv)
	witnessHash := witnessPubKey.Hash()
	cosignatures := []types.Cosignature{
		{CosignatureLine: *cosig1, WitnessID: witnessHash},
		// Missing second cosignature
	}

	// Try to create evidence - should fail at builder level
	_, err := evidence.CreateWitnessEquivocationEvidence(logIdentity, cp1, cp2, cosignatures, "test", "test")
	if err == nil {
		t.Error("expected error from builder for missing cosignature")
	}

	// Test with manually created bundle missing cosignatures
	eb := &evidence.EvidenceBundle{
		FormatVersion: evidence.EvidenceFormatVersion,
		LogIdentity:   logIdentity,
		Case:          evidence.EvidenceCaseWitnessEquivocation,
		Checkpoints:   []*types.Checkpoint{cp1, cp2},
		Cosignatures:  cosignatures, // Only 1
	}

	v := setupVerifier(&logPubKey, &witnessPubKey)
	result := v.VerifyBundle(eb)

	if result.Valid {
		t.Error("expected INVALID for missing required signature, got VALID")
	}
	found := false
	for _, e := range result.Errors {
		if contains(e, "cosignature") || contains(e, "at least 2") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected missing cosignature error, got: %v", result.Errors)
	}
}

// ============================================================================
// NEGATIVE TEST 9: Forged witness identity
// ============================================================================

func TestVerifier_ForgedWitnessIdentity(t *testing.T) {
	logPriv, logPubKey := generateKeyPair(t)
	witnessPriv, witnessPubKey := generateKeyPair(t)
	_, forgedWitnessPubKey := generateKeyPair(t)

	logIdentity := createTestLogIdentity(t, logPubKey)
	leaves := createTestLeaves(t, 10)

	cp1 := createTestCheckpoint(t, logPriv, logPubKey, 5, leaves)
	cp2 := createTestCheckpoint(t, logPriv, logPubKey, 10, leaves)

	// Valid cosignatures from real witness
	cosig1 := cp1.Checkpoint.SignCosignature(witnessPriv)
	cosig2 := cp2.Checkpoint.SignCosignature(witnessPriv)

	// But claim they're from a DIFFERENT (forged) witness identity
	forgedHash := forgedWitnessPubKey.Hash()
	cosignatures := []types.Cosignature{
		{CosignatureLine: *cosig1, WitnessID: forgedHash},
		{CosignatureLine: *cosig2, WitnessID: forgedHash},
	}

	eb, err := evidence.CreateWitnessEquivocationEvidence(logIdentity, cp1, cp2, cosignatures, "test", "test")
	if err != nil {
		t.Fatalf("failed to create evidence: %v", err)
	}

	// Verifier only trusts the REAL witness key, not the forged one
	v := setupVerifier(&logPubKey, &witnessPubKey)
	result := v.VerifyBundle(eb)

	if result.Valid {
		t.Error("expected INVALID for forged witness identity, got VALID")
	}
	found := false
	for _, e := range result.Errors {
		if contains(e, "witness") || contains(e, "not trusted") || contains(e, "public key") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected forged witness error, got: %v", result.Errors)
	}
}

// ============================================================================
// NEGATIVE TEST 10: Evidence containing unrelated checkpoints
// ============================================================================

func TestVerifier_UnrelatedCheckpoints(t *testing.T) {
	logPriv, logPubKey := generateKeyPair(t)
	_, otherLogPubKey := generateKeyPair(t)

	logIdentity := createTestLogIdentity(t, logPubKey)
	leaves := createTestLeaves(t, 10)

	// cp1 from logPubKey
	cp1 := createTestCheckpoint(t, logPriv, logPubKey, 10, leaves)

	// cp2 from DIFFERENT log (otherLogPubKey) - unrelated checkpoint
	otherLogPriv, _ := generateKeyPair(t)
	cp2 := createTestCheckpoint(t, otherLogPriv, otherLogPubKey, 10, createTestLeaves(t, 10))

	// But evidence claims both are from logPubKey
	cp2.LogID = logPubKey.Hash() // Lie about log ID

	eb, err := evidence.CreateSameSizeForkEvidence(logIdentity, cp1, cp2, "test", "test")
	if err != nil {
		t.Fatalf("failed to create evidence: %v", err)
	}

	v := setupVerifier(&logPubKey, nil)
	result := v.VerifyBundle(eb)

	if result.Valid {
		t.Error("expected INVALID for unrelated checkpoints, got VALID")
	}
	found := false
	for _, e := range result.Errors {
		if contains(e, "log ID") || contains(e, "mismatch") || contains(e, "signature") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected unrelated checkpoint error, got: %v", result.Errors)
	}
}

// ============================================================================
// NEGATIVE TEST 11: Unsupported evidence version
// ============================================================================

func TestVerifier_UnsupportedEvidenceVersion(t *testing.T) {
	logPriv, logPubKey := generateKeyPair(t)
	logIdentity := createTestLogIdentity(t, logPubKey)
	leaves := createTestLeaves(t, 10)

	cp1 := createTestCheckpoint(t, logPriv, logPubKey, 10, leaves)
	cp2 := createTestCheckpoint(t, logPriv, logPubKey, 10, createTestLeaves(t, 10))

	// Create valid evidence
	eb, err := evidence.CreateSameSizeForkEvidence(logIdentity, cp1, cp2, "test", "test")
	if err != nil {
		t.Fatalf("failed to create evidence: %v", err)
	}

	// Change format version to unsupported
	eb.FormatVersion = 999

	v := setupVerifier(&logPubKey, nil)
	result := v.VerifyBundle(eb)

	if result.Valid {
		t.Error("expected INVALID for unsupported evidence version, got VALID")
	}
	found := false
	for _, e := range result.Errors {
		if contains(e, "version") || contains(e, "unsupported") || contains(e, "format") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected version error, got: %v", result.Errors)
	}
}

// ============================================================================
// NEGATIVE TEST 12: Malformed serialization
// ============================================================================

func TestVerifier_MalformedSerialization(t *testing.T) {
	logPriv, logPubKey := generateKeyPair(t)
	v := setupVerifier(&logPubKey, nil)

	// Test various malformed inputs
	testCases := [][]byte{
		[]byte("not json at all"),
		[]byte("{invalid json"),
		[]byte("deadbeef"), // Invalid hex
		[]byte(""),         // Empty
		[]byte("\x00\x01\x02\x03"), // Random binary
	}

	for i, data := range testCases {
		result := v.VerifyBytes(data)
		if result.Valid {
			t.Errorf("test case %d: expected INVALID for malformed data, got VALID", i)
		}
		if len(result.Errors) == 0 {
			t.Errorf("test case %d: expected errors for malformed data", i)
		}
	}
}

// ============================================================================
// ADDITIONAL EDGE CASE TESTS
// ============================================================================

func TestVerifier_DifferentSizeFork_MissingTreeData(t *testing.T) {
	logPriv, logPubKey := generateKeyPair(t)
	logIdentity := createTestLogIdentity(t, logPubKey)
	leaves := createTestLeaves(t, 10)

	cpOld := createTestCheckpoint(t, logPriv, logPubKey, 5, leaves)
	cpNew := createTestCheckpoint(t, logPriv, logPubKey, 10, leaves)

	proofHashes := merkle.GenerateConsistencyProof(leaves[:5], 5, 10)
	consistencyProof := evidence.ConsistencyProofFromHashes(5, 10, proofHashes)

	// Create evidence WITHOUT tree data
	eb, err := evidence.CreateDifferentSizeForkEvidence(logIdentity, cpOld, cpNew, consistencyProof, nil, "test", "test")
	if err != nil {
		t.Fatalf("failed to create evidence: %v", err)
	}

	v := setupVerifier(&logPubKey, nil)
	result := v.VerifyBundle(eb)

	if result.Valid {
		t.Error("expected INVALID for missing tree data, got VALID")
	}
	found := false
	for _, e := range result.Errors {
		if contains(e, "tree data") || contains(e, "missing") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected missing tree data error, got: %v", result.Errors)
	}
}

func TestVerifier_DifferentSizeFork_WrongProofSizes(t *testing.T) {
	logPriv, logPubKey := generateKeyPair(t)
	logIdentity := createTestLogIdentity(t, logPubKey)
	leaves := createTestLeaves(t, 10)

	cpOld := createTestCheckpoint(t, logPriv, logPubKey, 5, leaves)
	cpNew := createTestCheckpoint(t, logPriv, logPubKey, 10, leaves)

	// Consistency proof with WRONG sizes
	proofHashes := merkle.GenerateConsistencyProof(leaves[:5], 5, 10)
	consistencyProof := evidence.ConsistencyProofFromHashes(3, 8, proofHashes) // Wrong sizes!
	treeData := evidence.TreeDataFromLeaves(leaves[:5])

	eb, err := evidence.CreateDifferentSizeForkEvidence(logIdentity, cpOld, cpNew, consistencyProof, treeData, "test", "test")
	if err != nil {
		t.Fatalf("failed to create evidence: %v", err)
	}

	v := setupVerifier(&logPubKey, nil)
	result := v.VerifyBundle(eb)

	if result.Valid {
		t.Error("expected INVALID for wrong proof sizes, got VALID")
	}
	found := false
	for _, e := range result.Errors {
		if contains(e, "size mismatch") || contains(e, "proof") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected proof size mismatch error, got: %v", result.Errors)
	}
}

func TestVerifier_SameSizeFork_SameRoot(t *testing.T) {
	logPriv, logPubKey := generateKeyPair(t)
	logIdentity := createTestLogIdentity(t, logPubKey)
	leaves := createTestLeaves(t, 10)

	cp1 := createTestCheckpoint(t, logPriv, logPubKey, 10, leaves)
	// cp2 is IDENTICAL to cp1 (same root) - not a fork
	cp2 := createTestCheckpoint(t, logPriv, logPubKey, 10, leaves)

	eb, err := evidence.CreateSameSizeForkEvidence(logIdentity, cp1, cp2, "test", "test")
	if err != nil {
		t.Fatalf("failed to create evidence: %v", err)
	}

	v := setupVerifier(&logPubKey, nil)
	result := v.VerifyBundle(eb)

	if result.Valid {
		t.Error("expected INVALID for same root (not a fork), got VALID")
	}
	found := false
	for _, e := range result.Errors {
		if contains(e, "same root") || contains(e, "not a fork") || contains(e, "different") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected same root error, got: %v", result.Errors)
	}
}

func TestVerifier_WitnessEquivocation_NonConflictingCheckpoints(t *testing.T) {
	logPriv, logPubKey := generateKeyPair(t)
	witnessPriv, witnessPubKey := generateKeyPair(t)

	logIdentity := createTestLogIdentity(t, logPubKey)
	leaves := createTestLeaves(t, 10)

	// Two IDENTICAL checkpoints - not conflicting
	cp1 := createTestCheckpoint(t, logPriv, logPubKey, 10, leaves)
	cp2 := createTestCheckpoint(t, logPriv, logPubKey, 10, leaves)

	cosig1 := cp1.Checkpoint.SignCosignature(witnessPriv)
	cosig2 := cp2.Checkpoint.SignCosignature(witnessPriv)

	witnessHash := witnessPubKey.Hash()
	cosignatures := []types.Cosignature{
		{CosignatureLine: *cosig1, WitnessID: witnessHash},
		{CosignatureLine: *cosig2, WitnessID: witnessHash},
	}

	eb, err := evidence.CreateWitnessEquivocationEvidence(logIdentity, cp1, cp2, cosignatures, "test", "test")
	if err != nil {
		t.Fatalf("failed to create evidence: %v", err)
	}

	v := setupVerifier(&logPubKey, &witnessPubKey)
	result := v.VerifyBundle(eb)

	if result.Valid {
		t.Error("expected INVALID for non-conflicting checkpoints, got VALID")
	}
	found := false
	for _, e := range result.Errors {
		if contains(e, "conflicting") || contains(e, "same") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected non-conflicting error, got: %v", result.Errors)
	}
}

func TestVerifier_WitnessEquivocation_CosignatureMismatch(t *testing.T) {
	logPriv, logPubKey := generateKeyPair(t)
	witnessPriv, witnessPubKey := generateKeyPair(t)

	logIdentity := createTestLogIdentity(t, logPubKey)
	leaves := createTestLeaves(t, 10)

	cp1 := createTestCheckpoint(t, logPriv, logPubKey, 5, leaves)
	cp2 := createTestCheckpoint(t, logPriv, logPubKey, 10, leaves)

	// Cosignature for cp1, but claim it's for cp2 (mismatch)
	cosig1 := cp1.Checkpoint.SignCosignature(witnessPriv)
	cosig2 := cp1.Checkpoint.SignCosignature(witnessPriv) // Same checkpoint!

	witnessHash := witnessPubKey.Hash()
	cosignatures := []types.Cosignature{
		{CosignatureLine: *cosig1, WitnessID: witnessHash},
		{CosignatureLine: *cosig2, WitnessID: witnessHash},
	}

	eb, err := evidence.CreateWitnessEquivocationEvidence(logIdentity, cp1, cp2, cosignatures, "test", "test")
	if err != nil {
		t.Fatalf("failed to create evidence: %v", err)
	}

	v := setupVerifier(&logPubKey, &witnessPubKey)
	result := v.VerifyBundle(eb)

	if result.Valid {
		t.Error("expected INVALID for cosignature mismatch, got VALID")
	}
	found := false
	for _, e := range result.Errors {
		if contains(e, "match") || contains(e, "cosignature") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected cosignature mismatch error, got: %v", result.Errors)
	}
}

func TestVerifier_UntrustedLogKey(t *testing.T) {
	logPriv, logPubKey := generateKeyPair(t)
	_, untrustedLogPubKey := generateKeyPair(t)

	// Verifier only trusts untrustedLogPubKey, not logPubKey
	v := NewVerifier()
	v.AddTrustedLogKey(&untrustedLogPubKey)

	logIdentity := createTestLogIdentity(t, logPubKey)
	leaves := createTestLeaves(t, 10)

	cp1 := createTestCheckpoint(t, logPriv, logPubKey, 10, leaves)
	cp2 := createTestCheckpoint(t, logPriv, logPubKey, 10, createTestLeaves(t, 10))

	eb, err := evidence.CreateSameSizeForkEvidence(logIdentity, cp1, cp2, "test", "test")
	if err != nil {
		t.Fatalf("failed to create evidence: %v", err)
	}

	result := v.VerifyBundle(eb)

	if result.Valid {
		t.Error("expected INVALID for untrusted log key, got VALID")
	}
	found := false
	for _, e := range result.Errors {
		if contains(e, "trusted") || contains(e, "log identity") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected untrusted log key error, got: %v", result.Errors)
	}
}

func TestVerifier_UntrustedWitnessKey(t *testing.T) {
	logPriv, logPubKey := generateKeyPair(t)
	witnessPriv, witnessPubKey := generateKeyPair(t)
	_, untrustedWitnessPubKey := generateKeyPair(t)

	// Verifier only trusts untrustedWitnessPubKey, not witnessPubKey
	v := NewVerifier()
	v.AddTrustedLogKey(&logPubKey)
	v.AddTrustedWitnessKey(&untrustedWitnessPubKey)

	logIdentity := createTestLogIdentity(t, logPubKey)
	leaves := createTestLeaves(t, 10)

	cp1 := createTestCheckpoint(t, logPriv, logPubKey, 5, leaves)
	cp2 := createTestCheckpoint(t, logPriv, logPubKey, 10, leaves)

	cosig1 := cp1.Checkpoint.SignCosignature(witnessPriv)
	cosig2 := cp2.Checkpoint.SignCosignature(witnessPriv)

	witnessHash := witnessPubKey.Hash()
	cosignatures := []types.Cosignature{
		{CosignatureLine: *cosig1, WitnessID: witnessHash},
		{CosignatureLine: *cosig2, WitnessID: witnessHash},
	}

	eb, err := evidence.CreateWitnessEquivocationEvidence(logIdentity, cp1, cp2, cosignatures, "test", "test")
	if err != nil {
		t.Fatalf("failed to create evidence: %v", err)
	}

	result := v.VerifyBundle(eb)

	if result.Valid {
		t.Error("expected INVALID for untrusted witness key, got VALID")
	}
	found := false
	for _, e := range result.Errors {
		if contains(e, "trusted") || contains(e, "witness") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected untrusted witness key error, got: %v", result.Errors)
	}
}

func TestVerifier_DeterministicBinaryFormat(t *testing.T) {
	logPriv, logPubKey := generateKeyPair(t)
	logIdentity := createTestLogIdentity(t, logPubKey)
	leaves := createTestLeaves(t, 10)

	cp1 := createTestCheckpoint(t, logPriv, logPubKey, 10, leaves)
	altLeaves := createTestLeaves(t, 10)
	altLeaves[5] = crypto.Hash{}
	cp2 := createTestCheckpoint(t, logPriv, logPubKey, 10, altLeaves)

	eb, err := evidence.CreateSameSizeForkEvidence(logIdentity, cp1, cp2, "test", "test")
	if err != nil {
		t.Fatalf("failed to create evidence: %v", err)
	}

	// Serialize to deterministic binary
	binaryData, err := eb.SerializeDeterministic()
	if err != nil {
		t.Fatalf("failed to serialize: %v", err)
	}

	// Verify from binary
	v := setupVerifier(&logPubKey, nil)
	result := v.VerifyBytes(binaryData)

	if !result.Valid {
		t.Errorf("expected VALID for binary format, got INVALID: %v", result.Errors)
	}
}

func TestVerifier_HexEncodedBinaryFormat(t *testing.T) {
	logPriv, logPubKey := generateKeyPair(t)
	logIdentity := createTestLogIdentity(t, logPubKey)
	leaves := createTestLeaves(t, 10)

	cp1 := createTestCheckpoint(t, logPriv, logPubKey, 10, leaves)
	altLeaves := createTestLeaves(t, 10)
	altLeaves[5] = crypto.Hash{}
	cp2 := createTestCheckpoint(t, logPriv, logPubKey, 10, altLeaves)

	eb, err := evidence.CreateSameSizeForkEvidence(logIdentity, cp1, cp2, "test", "test")
	if err != nil {
		t.Fatalf("failed to create evidence: %v", err)
	}

	// Serialize to hex-encoded binary
	hexStr, err := eb.HexEncode()
	if err != nil {
		t.Fatalf("failed to hex encode: %v", err)
	}

	// Verify from hex
	v := setupVerifier(&logPubKey, nil)
	result := v.VerifyBytes([]byte(hexStr))

	if !result.Valid {
		t.Errorf("expected VALID for hex format, got INVALID: %v", result.Errors)
	}
}

func TestVerifier_StandaloneConsistencyProofVerification(t *testing.T) {
	leaves := createTestLeaves(t, 10)

	// Valid proof
	proofHashes := merkle.GenerateConsistencyProof(leaves[:5], 5, 10)
	oldRoot := merkle.ComputeRootHash(leaves[:5])
	newRoot := merkle.ComputeRootHash(leaves[:10])

	err := VerifyMerkleConsistencyProof(leaves[:5], proofHashes, 5, 10, oldRoot, newRoot)
	if err != nil {
		t.Errorf("valid proof failed: %v", err)
	}

	// Invalid proof (wrong hashes)
	badProofHashes := []crypto.Hash{crypto.Hash{1, 2, 3, 4}}
	err = VerifyMerkleConsistencyProof(leaves[:5], badProofHashes, 5, 10, oldRoot, newRoot)
	if err == nil {
		t.Error("expected error for invalid proof, got nil")
	}

	// Wrong expected roots
	err = VerifyMerkleConsistencyProof(leaves[:5], proofHashes, 5, 10, crypto.Hash{}, newRoot)
	if err == nil {
		t.Error("expected error for wrong old root, got nil")
	}
}

func TestVerifier_StandaloneInclusionProofVerification(t *testing.T) {
	leaves := createTestLeaves(t, 10)
	root := merkle.ComputeRootHash(leaves)

	// Generate inclusion proof for leaf 3
	proofHashes := merkle.GenerateInclusionProof(leaves, 3, 10)

	// Valid proof
	valid := VerifyMerkleInclusionProof(3, 10, proofHashes, root)
	if !valid {
		t.Error("valid inclusion proof failed")
	}

	// Invalid proof (wrong root)
	valid = VerifyMerkleInclusionProof(3, 10, proofHashes, crypto.Hash{})
	if valid {
		t.Error("expected invalid for wrong root")
	}

	// Invalid proof (wrong leaf index)
	valid = VerifyMerkleInclusionProof(5, 10, proofHashes, root)
	if valid {
		t.Error("expected invalid for wrong leaf index")
	}
}

// Helper function
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && findSubstring(s, substr))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// Benchmark tests
func BenchmarkVerifier_SameSizeFork(b *testing.B) {
	logPriv, logPubKey := generateKeyPair(&testing.B{})
	logIdentity := createTestLogIdentity(&testing.B{}, logPubKey)
	leaves := createTestLeaves(&testing.B{}, 100)

	cp1 := createTestCheckpoint(&testing.B{}, logPriv, logPubKey, 100, leaves)
	altLeaves := createTestLeaves(&testing.B{}, 100)
	altLeaves[50] = crypto.Hash{}
	cp2 := createTestCheckpoint(&testing.B{}, logPriv, logPubKey, 100, altLeaves)

	eb, _ := evidence.CreateSameSizeForkEvidence(logIdentity, cp1, cp2, "bench", "bench")
	v := setupVerifier(&logPubKey, nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		v.VerifyBundle(eb)
	}
}

func BenchmarkVerifier_DifferentSizeFork(b *testing.B) {
	logPriv, logPubKey := generateKeyPair(&testing.B{})
	logIdentity := createTestLogIdentity(&testing.B{}, logPubKey)
	leaves := createTestLeaves(&testing.B{}, 100)

	cpOld := createTestCheckpoint(&testing.B{}, logPriv, logPubKey, 50, leaves)
	cpNew := createTestCheckpoint(&testing.B{}, logPriv, logPubKey, 100, leaves)

	proofHashes := merkle.GenerateConsistencyProof(leaves[:50], 50, 100)
	consistencyProof := evidence.ConsistencyProofFromHashes(50, 100, proofHashes)
	treeData := evidence.TreeDataFromLeaves(leaves[:50])

	eb, _ := evidence.CreateDifferentSizeForkEvidence(logIdentity, cpOld, cpNew, consistencyProof, treeData, "bench", "bench")
	v := setupVerifier(&logPubKey, nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		v.VerifyBundle(eb)
	}
}