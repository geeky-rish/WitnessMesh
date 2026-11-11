// Package evidence implements the evidence engine for generating and verifying
// cryptographically verifiable evidence bundles for transparency log anomalies.
//
// Evidence bundles are portable, independently verifiable, and use deterministic
// serialization where practical. Cryptographic evidence is separated from
// descriptive metadata to enable clear verification logic.
//
// Supported evidence cases:
// 1. SameSizeFork: Two checkpoints with same log ID, same tree size, different roots,
//    both with valid log signatures.
// 2. DifferentSizeFork: Two checkpoints at different tree sizes with a consistency
//    proof and authenticated tree data demonstrating forked history.
// 3. WitnessEquivocation: A single witness signing two conflicting checkpoints.
package evidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"time"

	"sigsum.org/sigsum-go/pkg/checkpoint"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/merkle"

	"witnessmesh/internal/types"
)

// EvidenceFormatVersion is the current format version for evidence bundles.
// Increment when making backward-incompatible changes to the serialization format.
const EvidenceFormatVersion = 1

// EvidenceCase represents the type of evidence contained in a bundle.
type EvidenceCase int

const (
	// EvidenceCaseSameSizeFork: Two checkpoints with same log ID, same tree size,
	// different root hashes, both with valid log signatures.
	EvidenceCaseSameSizeFork EvidenceCase = iota + 1

	// EvidenceCaseDifferentSizeFork: Two checkpoints at different tree sizes with
	// a consistency proof and authenticated tree data demonstrating forked history.
	EvidenceCaseDifferentSizeFork

	// EvidenceCaseWitnessEquivocation: A single witness signing two conflicting
	// checkpoints (different log ID, size, or root hash).
	EvidenceCaseWitnessEquivocation
)

// String returns the string representation of the evidence case.
func (ec EvidenceCase) String() string {
	switch ec {
	case EvidenceCaseSameSizeFork:
		return "same_size_fork"
	case EvidenceCaseDifferentSizeFork:
		return "different_size_fork"
	case EvidenceCaseWitnessEquivocation:
		return "witness_equivocation"
	default:
		return fmt.Sprintf("unknown(%d)", ec)
	}
}

// MarshalJSON implements custom JSON marshaling for EvidenceCase.
func (ec EvidenceCase) MarshalJSON() ([]byte, error) {
	return json.Marshal(ec.String())
}

// UnmarshalJSON implements custom JSON unmarshaling for EvidenceCase.
func (ec *EvidenceCase) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	switch s {
	case "same_size_fork":
		*ec = EvidenceCaseSameSizeFork
	case "different_size_fork":
		*ec = EvidenceCaseDifferentSizeFork
	case "witness_equivocation":
		*ec = EvidenceCaseWitnessEquivocation
	default:
		return fmt.Errorf("unknown evidence case: %s", s)
	}
	return nil
}

// EvidenceBundle is a cryptographically verifiable evidence bundle.
//
// The bundle contains all cryptographic material needed for independent verification
// of a transparency log anomaly, separated from descriptive metadata.
//
// Serialization is deterministic: JSON fields are sorted, timestamps use RFC3339Nano,
// and binary encodings use fixed-width big-endian integers.
type EvidenceBundle struct {
	// FormatVersion is the evidence format version for forward compatibility.
	FormatVersion int `json:"format_version"`

	// LogIdentity identifies the transparency log involved.
	LogIdentity types.LogIdentity `json:"log_identity"`

	// Case is the type of evidence this bundle proves.
	Case EvidenceCase `json:"case"`

	// Checkpoints are the checkpoint(s) forming the basis of the evidence.
	// For same-size fork: 2 checkpoints at same size, different roots.
	// For different-size fork: 2 checkpoints at different sizes.
	// For witness equivocation: 2 checkpoints cosigned by the same witness.
	Checkpoints []*types.Checkpoint `json:"checkpoints"`

	// Cosignatures are the witness cosignatures on the checkpoints.
	// Required for witness equivocation; optional for fork evidence.
	Cosignatures []types.Cosignature `json:"cosignatures,omitempty"`

	// ConsistencyProof is the Merkle consistency proof between two tree sizes.
	// Required for different-size fork evidence.
	ConsistencyProof *ConsistencyProof `json:"consistency_proof,omitempty"`

	// TreeData contains authenticated tree data for different-size fork evidence.
	// Includes leaf hashes or inclusion proofs needed to verify the consistency proof.
	TreeData *TreeData `json:"tree_data,omitempty"`

	// DetectionMetadata contains descriptive metadata about the detection.
	// This is NOT part of the cryptographic evidence and is excluded from
	// deterministic serialization used for hashing/signing.
	DetectionMetadata DetectionMetadata `json:"detection_metadata"`

	// CreatedAt is the timestamp when this evidence bundle was created.
	CreatedAt time.Time `json:"created_at"`
}

// DetectionMetadata contains descriptive metadata about evidence detection.
// This is separated from cryptographic evidence to keep verification pure.
type DetectionMetadata struct {
	// DetectorID identifies the component that detected the anomaly.
	DetectorID string `json:"detector_id"`

	// DetectionTime is when the anomaly was detected.
	DetectionTime time.Time `json:"detection_time"`

	// Source describes where the evidence was obtained (e.g., "log", "witness", "gossip").
	Source string `json:"source"`

	// Additional context as key-value pairs.
	Context map[string]string `json:"context,omitempty"`
}

// ConsistencyProof represents a Merkle consistency proof between two tree sizes.
//
// The proof allows verification that the tree of size NewSize is an extension
// of the tree of size OldSize (i.e., the first OldSize leaves are identical).
// The Hashes array contains the minimal set of intermediate hashes needed
// to compute both root hashes from the leaves, per RFC 6962.
type ConsistencyProof struct {
	OldSize uint64        `json:"old_size"`
	NewSize uint64        `json:"new_size"`
	Hashes  []crypto.Hash `json:"hashes"`
}

// TreeData contains authenticated tree data for verifying consistency proofs.
//
// For different-size fork evidence, this provides the leaf hashes or inclusion
// proofs needed to independently verify the consistency proof without trusting
// the log's current state.
type TreeData struct {
	// Leaves are the leaf hashes for the tree at OldSize.
	// Used to verify the consistency proof from the old tree root.
	Leaves []crypto.Hash `json:"leaves,omitempty"`

	// InclusionProofs are inclusion proofs for specific leaves at OldSize.
	// Alternative to providing all leaves when only a subset is needed.
	InclusionProofs []InclusionProof `json:"inclusion_proofs,omitempty"`
}

// InclusionProof represents a Merkle inclusion proof for a single leaf.
type InclusionProof struct {
	LeafIndex uint64        `json:"leaf_index"`
	TreeSize  uint64        `json:"tree_size"`
	Hashes    []crypto.Hash `json:"hashes"`
}

// EvidenceBuilder helps construct evidence bundles with validation.
type EvidenceBuilder struct {
	bundle *EvidenceBundle
	err    error
}

// NewEvidenceBuilder creates a new evidence builder.
func NewEvidenceBuilder() *EvidenceBuilder {
	return &EvidenceBuilder{
		bundle: &EvidenceBundle{
			FormatVersion: EvidenceFormatVersion,
			CreatedAt:     time.Now().UTC(),
			DetectionMetadata: DetectionMetadata{
				DetectionTime: time.Now().UTC(),
				Context:       make(map[string]string),
			},
		},
	}
}

// WithLogIdentity sets the log identity.
func (b *EvidenceBuilder) WithLogIdentity(logID types.LogIdentity) *EvidenceBuilder {
	if b.err != nil {
		return b
	}
	b.bundle.LogIdentity = logID
	return b
}

// WithCase sets the evidence case.
func (b *EvidenceBuilder) WithCase(caseType EvidenceCase) *EvidenceBuilder {
	if b.err != nil {
		return b
	}
	b.bundle.Case = caseType
	return b
}

// WithCheckpoints sets the checkpoints.
func (b *EvidenceBuilder) WithCheckpoints(checkpoints []*types.Checkpoint) *EvidenceBuilder {
	if b.err != nil {
		return b
	}
	b.bundle.Checkpoints = checkpoints
	return b
}

// WithCosignatures sets the witness cosignatures.
func (b *EvidenceBuilder) WithCosignatures(cosigs []types.Cosignature) *EvidenceBuilder {
	if b.err != nil {
		return b
	}
	b.bundle.Cosignatures = cosigs
	return b
}

// WithConsistencyProof sets the consistency proof.
func (b *EvidenceBuilder) WithConsistencyProof(proof *ConsistencyProof) *EvidenceBuilder {
	if b.err != nil {
		return b
	}
	b.bundle.ConsistencyProof = proof
	return b
}

// WithTreeData sets the tree data.
func (b *EvidenceBuilder) WithTreeData(data *TreeData) *EvidenceBuilder {
	if b.err != nil {
		return b
	}
	b.bundle.TreeData = data
	return b
}

// WithDetectionMetadata sets the detection metadata.
func (b *EvidenceBuilder) WithDetectionMetadata(meta DetectionMetadata) *EvidenceBuilder {
	if b.err != nil {
		return b
	}
	b.bundle.DetectionMetadata = meta
	return b
}

// WithDetectorID sets the detector ID.
func (b *EvidenceBuilder) WithDetectorID(detectorID string) *EvidenceBuilder {
	if b.err != nil {
		return b
	}
	b.bundle.DetectionMetadata.DetectorID = detectorID
	return b
}

// WithSource sets the evidence source.
func (b *EvidenceBuilder) WithSource(source string) *EvidenceBuilder {
	if b.err != nil {
		return b
	}
	b.bundle.DetectionMetadata.Source = source
	return b
}

// WithContext adds context to detection metadata.
func (b *EvidenceBuilder) WithContext(key, value string) *EvidenceBuilder {
	if b.err != nil {
		return b
	}
	if b.bundle.DetectionMetadata.Context == nil {
		b.bundle.DetectionMetadata.Context = make(map[string]string)
	}
	b.bundle.DetectionMetadata.Context[key] = value
	return b
}

// Build validates and returns the evidence bundle.
func (b *EvidenceBuilder) Build() (*EvidenceBundle, error) {
	if b.err != nil {
		return nil, b.err
	}

	// Validate required fields
	if b.bundle.LogIdentity.PublicKey == (crypto.PublicKey{}) {
		b.err = fmt.Errorf("log identity is required")
		return nil, b.err
	}

	if b.bundle.Case == 0 {
		b.err = fmt.Errorf("evidence case is required")
		return nil, b.err
	}

	if len(b.bundle.Checkpoints) == 0 {
		b.err = fmt.Errorf("at least one checkpoint is required")
		return nil, b.err
	}

	// Case-specific validation
	switch b.bundle.Case {
	case EvidenceCaseSameSizeFork:
		if len(b.bundle.Checkpoints) != 2 {
			b.err = fmt.Errorf("same-size fork requires exactly 2 checkpoints")
			return nil, b.err
		}
		cp1, cp2 := b.bundle.Checkpoints[0], b.bundle.Checkpoints[1]
		if cp1.Checkpoint.SignedTreeHead.Size != cp2.Checkpoint.SignedTreeHead.Size {
			b.err = fmt.Errorf("same-size fork checkpoints must have same tree size")
			return nil, b.err
		}
		if cp1.Checkpoint.SignedTreeHead.RootHash == cp2.Checkpoint.SignedTreeHead.RootHash {
			b.err = fmt.Errorf("same-size fork checkpoints must have different root hashes")
			return nil, b.err
		}
		if cp1.LogID != cp2.LogID {
			b.err = fmt.Errorf("same-size fork checkpoints must have same log ID")
			return nil, b.err
		}
		// Both must have valid log signatures
		if err := cp1.Checkpoint.Verify(&b.bundle.LogIdentity.PublicKey); err != nil {
			b.err = fmt.Errorf("first checkpoint signature invalid: %w", err)
			return nil, b.err
		}
		if err := cp2.Checkpoint.Verify(&b.bundle.LogIdentity.PublicKey); err != nil {
			b.err = fmt.Errorf("second checkpoint signature invalid: %w", err)
			return nil, b.err
		}

	case EvidenceCaseDifferentSizeFork:
		if len(b.bundle.Checkpoints) != 2 {
			b.err = fmt.Errorf("different-size fork requires exactly 2 checkpoints")
			return nil, b.err
		}
		cp1, cp2 := b.bundle.Checkpoints[0], b.bundle.Checkpoints[1]
		if cp1.LogID != cp2.LogID {
			b.err = fmt.Errorf("different-size fork checkpoints must have same log ID")
			return nil, b.err
		}
		if cp1.Checkpoint.SignedTreeHead.Size >= cp2.Checkpoint.SignedTreeHead.Size {
			b.err = fmt.Errorf("first checkpoint size must be less than second")
			return nil, b.err
		}
		// Both must have valid log signatures
		if err := cp1.Checkpoint.Verify(&b.bundle.LogIdentity.PublicKey); err != nil {
			b.err = fmt.Errorf("first checkpoint signature invalid: %w", err)
			return nil, b.err
		}
		if err := cp2.Checkpoint.Verify(&b.bundle.LogIdentity.PublicKey); err != nil {
			b.err = fmt.Errorf("second checkpoint signature invalid: %w", err)
			return nil, b.err
		}
		if b.bundle.ConsistencyProof == nil {
			b.err = fmt.Errorf("different-size fork requires consistency proof")
			return nil, b.err
		}
		if b.bundle.ConsistencyProof.OldSize != cp1.Checkpoint.SignedTreeHead.Size {
			b.err = fmt.Errorf("consistency proof old size must match first checkpoint size")
			return nil, b.err
		}
		if b.bundle.ConsistencyProof.NewSize != cp2.Checkpoint.SignedTreeHead.Size {
			b.err = fmt.Errorf("consistency proof new size must match second checkpoint size")
			return nil, b.err
		}

	case EvidenceCaseWitnessEquivocation:
		if len(b.bundle.Checkpoints) != 2 {
			b.err = fmt.Errorf("witness equivocation requires exactly 2 checkpoints")
			return nil, b.err
		}
		if len(b.bundle.Cosignatures) < 2 {
			b.err = fmt.Errorf("witness equivocation requires at least 2 cosignatures")
			return nil, b.err
		}
		// Verify both cosignatures are from the same witness
		witnessHash := b.bundle.Cosignatures[0].WitnessID
		for _, cosig := range b.bundle.Cosignatures[1:] {
			if cosig.WitnessID != witnessHash {
				b.err = fmt.Errorf("all cosignatures must be from the same witness")
				return nil, b.err
			}
		}
		// Verify the checkpoints are conflicting (different log ID, size, or root)
		cp1, cp2 := b.bundle.Checkpoints[0], b.bundle.Checkpoints[1]
		sameLogID := cp1.LogID == cp2.LogID
		sameSize := cp1.Checkpoint.SignedTreeHead.Size == cp2.Checkpoint.SignedTreeHead.Size
		sameRoot := cp1.Checkpoint.SignedTreeHead.RootHash == cp2.Checkpoint.SignedTreeHead.RootHash
		if sameLogID && sameSize && sameRoot {
			b.err = fmt.Errorf("checkpoints must be conflicting (different log ID, size, or root)")
			return nil, b.err
		}
		// Verify each cosignature matches its corresponding checkpoint
		for _, cosig := range b.bundle.Cosignatures {
			found := false
			for _, cp := range b.bundle.Checkpoints {
				if cp.Checkpoint.SignedTreeHead.Size == cosig.Cosignature.TreeSize &&
					cp.Checkpoint.SignedTreeHead.RootHash == cosig.Cosignature.RootHash {
					found = true
					break
				}
			}
			if !found {
				b.err = fmt.Errorf("cosignature does not match any checkpoint")
				return nil, b.err
			}
		}

	default:
		b.err = fmt.Errorf("unknown evidence case: %d", b.bundle.Case)
		return nil, b.err
	}

	// Set creation time
	b.bundle.CreatedAt = time.Now().UTC()

	return b.bundle, nil
}

// DeterministicMarshal returns a deterministic byte representation of the evidence bundle
// suitable for hashing, signing, or content-addressing.
// Excludes DetectionMetadata as it is descriptive, not cryptographic.
func (eb *EvidenceBundle) DeterministicMarshal() ([]byte, error) {
	// Create a copy with only cryptographic fields
	cryptoBundle := struct {
		FormatVersion   int                   `json:"format_version"`
		LogIdentity     types.LogIdentity     `json:"log_identity"`
		Case            EvidenceCase          `json:"case"`
		Checkpoints     []*types.Checkpoint   `json:"checkpoints"`
		Cosignatures    []types.Cosignature   `json:"cosignatures,omitempty"`
		ConsistencyProof *ConsistencyProof    `json:"consistency_proof,omitempty"`
		TreeData        *TreeData             `json:"tree_data,omitempty"`
	}{
		FormatVersion:    eb.FormatVersion,
		LogIdentity:      eb.LogIdentity,
		Case:             eb.Case,
		Checkpoints:      eb.Checkpoints,
		Cosignatures:     eb.Cosignatures,
		ConsistencyProof: eb.ConsistencyProof,
		TreeData:         eb.TreeData,
	}

	// Use JSON with sorted keys for deterministic output
	return json.Marshal(cryptoBundle)
}

// MarshalJSON implements custom JSON marshaling for EvidenceBundle.
func (eb *EvidenceBundle) MarshalJSON() ([]byte, error) {
	type Alias EvidenceBundle
	return json.Marshal(&struct {
		*Alias
		CreatedAt string `json:"created_at"`
	}{
		Alias:     (*Alias)(eb),
		CreatedAt: eb.CreatedAt.UTC().Format(time.RFC3339Nano),
	})
}

// UnmarshalJSON implements custom JSON unmarshaling for EvidenceBundle.
func (eb *EvidenceBundle) UnmarshalJSON(data []byte) error {
	type Alias EvidenceBundle
	aux := &struct {
		*Alias
		CreatedAt string `json:"created_at"`
	}{
		Alias: (*Alias)(eb),
	}
	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}
	if aux.CreatedAt != "" {
		t, err := time.Parse(time.RFC3339Nano, aux.CreatedAt)
		if err != nil {
			return err
		}
		eb.CreatedAt = t
	}
	return nil
}

// Hash computes the SHA-256 hash of the deterministic serialization.
func (eb *EvidenceBundle) Hash() (crypto.Hash, error) {
	data, err := eb.DeterministicMarshal()
	if err != nil {
		return crypto.Hash{}, err
	}
	sum := sha256.Sum256(data)
	return crypto.Hash(sum), nil
}

// Verify verifies the evidence bundle against the provided log public key
// and witness public keys. Returns a VerificationResult with details.
func (eb *EvidenceBundle) Verify(logPubKey *crypto.PublicKey, witnessPubKeys map[crypto.Hash]*crypto.PublicKey) *types.VerificationResult {
	result := &types.VerificationResult{
		Valid:  true,
		Case:   eb.Case,
		Errors: nil,
	}

	// Verify log identity matches
	if eb.LogIdentity.PublicKey != *logPubKey {
		result.Valid = false
		result.Errors = append(result.Errors, "log identity public key mismatch")
		return result
	}

	// Verify all checkpoint signatures
	for i, cp := range eb.Checkpoints {
		if err := cp.Checkpoint.Verify(logPubKey); err != nil {
			result.Valid = false
			result.Errors = append(result.Errors, fmt.Sprintf("checkpoint %d signature invalid: %v", i, err))
		}
	}

	// Case-specific verification
	switch eb.Case {
	case EvidenceCaseSameSizeFork:
		result.Description = "Same-size fork: two checkpoints with same log ID and size, different roots"
		if len(eb.Checkpoints) != 2 {
			result.Valid = false
			result.Errors = append(result.Errors, "same-size fork requires exactly 2 checkpoints")
		} else {
			cp1, cp2 := eb.Checkpoints[0], eb.Checkpoints[1]
			if cp1.Checkpoint.SignedTreeHead.Size != cp2.Checkpoint.SignedTreeHead.Size {
				result.Valid = false
				result.Errors = append(result.Errors, "checkpoints have different tree sizes")
			}
			if cp1.Checkpoint.SignedTreeHead.RootHash == cp2.Checkpoint.SignedTreeHead.RootHash {
				result.Valid = false
				result.Errors = append(result.Errors, "checkpoints have same root hash (not a fork)")
			}
			if cp1.LogID != cp2.LogID {
				result.Valid = false
				result.Errors = append(result.Errors, "checkpoints have different log IDs")
			}
		}

	case EvidenceCaseDifferentSizeFork:
		result.Description = "Different-size fork: two checkpoints at different sizes with consistency proof"
		if len(eb.Checkpoints) != 2 {
			result.Valid = false
			result.Errors = append(result.Errors, "different-size fork requires exactly 2 checkpoints")
		} else if eb.ConsistencyProof == nil {
			result.Valid = false
			result.Errors = append(result.Errors, "missing consistency proof")
		} else {
			cp1, cp2 := eb.Checkpoints[0], eb.Checkpoints[1]
			if cp1.LogID != cp2.LogID {
				result.Valid = false
				result.Errors = append(result.Errors, "checkpoints have different log IDs")
			}
			if cp1.Checkpoint.SignedTreeHead.Size >= cp2.Checkpoint.SignedTreeHead.Size {
				result.Valid = false
				result.Errors = append(result.Errors, "first checkpoint size not less than second")
			}
			// Verify consistency proof
			if eb.ConsistencyProof != nil {
				if eb.ConsistencyProof.OldSize != cp1.Checkpoint.SignedTreeHead.Size {
					result.Valid = false
					result.Errors = append(result.Errors, "consistency proof old size mismatch")
				}
				if eb.ConsistencyProof.NewSize != cp2.Checkpoint.SignedTreeHead.Size {
					result.Valid = false
					result.Errors = append(result.Errors, "consistency proof new size mismatch")
				}
				// Note: Full consistency proof verification requires the leaf hashes
				// which are in TreeData. This is verified separately if TreeData is present.
				if eb.TreeData != nil {
					if err := verifyConsistencyProof(eb.ConsistencyProof, eb.TreeData, cp1, cp2); err != nil {
						result.Valid = false
						result.Errors = append(result.Errors, fmt.Sprintf("consistency proof verification failed: %v", err))
					}
				}
			}
		}

	case EvidenceCaseWitnessEquivocation:
		result.Description = "Witness equivocation: single witness signing conflicting checkpoints"
		if len(eb.Checkpoints) != 2 {
			result.Valid = false
			result.Errors = append(result.Errors, "witness equivocation requires exactly 2 checkpoints")
		}
		if len(eb.Cosignatures) < 2 {
			result.Valid = false
			result.Errors = append(result.Errors, "witness equivocation requires at least 2 cosignatures")
		}
		// Verify all cosignatures are from same witness
		if len(eb.Cosignatures) >= 2 {
			witnessHash := eb.Cosignatures[0].WitnessID
			witnessPubKey, ok := witnessPubKeys[witnessHash]
			if !ok {
				result.Valid = false
				result.Errors = append(result.Errors, "witness public key not provided")
			} else {
				for i, cosig := range eb.Cosignatures {
					if cosig.WitnessID != witnessHash {
						result.Valid = false
						result.Errors = append(result.Errors, fmt.Sprintf("cosignature %d from different witness", i))
						continue
					}
					// Find matching checkpoint
					var matchedCP *types.Checkpoint
					for _, cp := range eb.Checkpoints {
						if cp.Checkpoint.SignedTreeHead.Size == cosig.Cosignature.TreeSize &&
							cp.Checkpoint.SignedTreeHead.RootHash == cosig.Cosignature.RootHash {
							matchedCP = cp
							break
						}
					}
					if matchedCP == nil {
						result.Valid = false
						result.Errors = append(result.Errors, fmt.Sprintf("cosignature %d does not match any checkpoint", i))
						continue
					}
					// Verify cosignature
					if !matchedCP.Checkpoint.VerifyCosignature(witnessPubKey, &cosig.Cosignature) {
						result.Valid = false
						result.Errors = append(result.Errors, fmt.Sprintf("cosignature %d verification failed", i))
					}
				}
			}
		}
		// Verify checkpoints are conflicting
		if len(eb.Checkpoints) == 2 {
			cp1, cp2 := eb.Checkpoints[0], eb.Checkpoints[1]
			sameLogID := cp1.LogID == cp2.LogID
			sameSize := cp1.Checkpoint.SignedTreeHead.Size == cp2.Checkpoint.SignedTreeHead.Size
			sameRoot := cp1.Checkpoint.SignedTreeHead.RootHash == cp2.Checkpoint.SignedTreeHead.RootHash
			if sameLogID && sameSize && sameRoot {
				result.Valid = false
				result.Errors = append(result.Errors, "checkpoints are not conflicting")
			}
		}

	default:
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("unknown evidence case: %d", eb.Case))
	}

	return result
}

// verifyConsistencyProof verifies a consistency proof using the provided tree data.
// This implements RFC 6962 consistency proof verification.
func verifyConsistencyProof(proof *ConsistencyProof, treeData *TreeData, cpOld, cpNew *types.Checkpoint) error {
	// If we have all leaves, we can verify directly
	if len(treeData.Leaves) > 0 {
		if uint64(len(treeData.Leaves)) != proof.OldSize {
			return fmt.Errorf("leaf count (%d) does not match old size (%d)", len(treeData.Leaves), proof.OldSize)
		}

		// Compute old root from leaves
		computedOldRoot := merkle.ComputeRootHash(treeData.Leaves)
		if computedOldRoot != cpOld.Checkpoint.SignedTreeHead.RootHash {
			return fmt.Errorf("computed old root does not match checkpoint")
		}

		// Compute new root using consistency proof
		// The proof provides the intermediate hashes needed to compute the new root
		computedNewRoot := merkle.VerifyConsistencyProof(
			treeData.Leaves,
			proof.Hashes,
			proof.OldSize,
			proof.NewSize,
		)
		if computedNewRoot != cpNew.Checkpoint.SignedTreeHead.RootHash {
			return fmt.Errorf("consistency proof does not yield new root hash")
		}

		return nil
	}

	// If we have inclusion proofs, verify each one
	if len(treeData.InclusionProofs) > 0 {
		for _, incProof := range treeData.InclusionProofs {
			// Verify inclusion proof against old checkpoint
			if incProof.TreeSize != cpOld.Checkpoint.SignedTreeHead.Size {
				return fmt.Errorf("inclusion proof tree size mismatch")
			}
			if !merkle.VerifyInclusionProof(incProof.LeafIndex, incProof.Hashes, incProof.TreeSize, cpOld.Checkpoint.SignedTreeHead.RootHash) {
				return fmt.Errorf("inclusion proof verification failed for leaf %d", incProof.LeafIndex)
			}
		}
		// Note: With only inclusion proofs, we cannot fully verify the consistency
		// proof without the full leaf set. This is a partial verification.
		return nil
	}

	return fmt.Errorf("no tree data provided for consistency proof verification")
}

// WriteTo writes the evidence bundle in deterministic JSON format to the writer.
func (eb *EvidenceBundle) WriteTo(w io.Writer) (int64, error) {
	data, err := json.MarshalIndent(eb, "", "  ")
	if err != nil {
		return 0, err
	}
	n, err := w.Write(data)
	return int64(n), err
}

// ReadFrom reads an evidence bundle from the reader.
func ReadFrom(r io.Reader) (*EvidenceBundle, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	var eb EvidenceBundle
	if err := json.Unmarshal(data, &eb); err != nil {
		return nil, err
	}
	return &eb, nil
}

// CreateSameSizeForkEvidence creates evidence for a same-size fork.
// Both checkpoints must have valid log signatures, same log ID, same tree size,
// but different root hashes.
func CreateSameSizeForkEvidence(
	logIdentity types.LogIdentity,
	cp1, cp2 *types.Checkpoint,
	detectorID, source string,
) (*EvidenceBundle, error) {
	return NewEvidenceBuilder().
		WithLogIdentity(logIdentity).
		WithCase(EvidenceCaseSameSizeFork).
		WithCheckpoints([]*types.Checkpoint{cp1, cp2}).
		WithDetectorID(detectorID).
		WithSource(source).
		Build()
}

// CreateDifferentSizeForkEvidence creates evidence for a different-size fork.
// Both checkpoints must have valid log signatures, same log ID, different sizes.
// Requires a consistency proof and optionally tree data for verification.
func CreateDifferentSizeForkEvidence(
	logIdentity types.LogIdentity,
	cpOld, cpNew *types.Checkpoint,
	consistencyProof *ConsistencyProof,
	treeData *TreeData,
	detectorID, source string,
) (*EvidenceBundle, error) {
	if cpOld.Checkpoint.SignedTreeHead.Size >= cpNew.Checkpoint.SignedTreeHead.Size {
		return nil, fmt.Errorf("old checkpoint size must be less than new checkpoint size")
	}
	return NewEvidenceBuilder().
		WithLogIdentity(logIdentity).
		WithCase(EvidenceCaseDifferentSizeFork).
		WithCheckpoints([]*types.Checkpoint{cpOld, cpNew}).
		WithConsistencyProof(consistencyProof).
		WithTreeData(treeData).
		WithDetectorID(detectorID).
		WithSource(source).
		Build()
}

// CreateWitnessEquivocationEvidence creates evidence for witness equivocation.
// Requires two checkpoints and cosignatures from the same witness on both.
// The checkpoints must be conflicting (different log ID, size, or root).
func CreateWitnessEquivocationEvidence(
	logIdentity types.LogIdentity,
	cp1, cp2 *types.Checkpoint,
	cosignatures []types.Cosignature,
	detectorID, source string,
) (*EvidenceBundle, error) {
	if len(cosignatures) < 2 {
		return nil, fmt.Errorf("at least 2 cosignatures required")
	}
	// Verify all cosignatures are from same witness
	witnessHash := cosignatures[0].WitnessID
	for _, cosig := range cosignatures[1:] {
		if cosig.WitnessID != witnessHash {
			return nil, fmt.Errorf("all cosignatures must be from same witness")
		}
	}
	return NewEvidenceBuilder().
		WithLogIdentity(logIdentity).
		WithCase(EvidenceCaseWitnessEquivocation).
		WithCheckpoints([]*types.Checkpoint{cp1, cp2}).
		WithCosignatures(cosignatures).
		WithDetectorID(detectorID).
		WithSource(source).
		Build()
}

// ConsistencyProofFromHashes creates a consistency proof from a slice of hashes.
func ConsistencyProofFromHashes(oldSize, newSize uint64, hashes []crypto.Hash) *ConsistencyProof {
	// Make a copy to avoid external mutation
	hashesCopy := make([]crypto.Hash, len(hashes))
	copy(hashesCopy, hashes)
	return &ConsistencyProof{
		OldSize: oldSize,
		NewSize: newSize,
		Hashes:  hashesCopy,
	}
}

// TreeDataFromLeaves creates tree data from leaf hashes.
func TreeDataFromLeaves(leaves []crypto.Hash) *TreeData {
	leavesCopy := make([]crypto.Hash, len(leaves))
	copy(leavesCopy, leaves)
	return &TreeData{
		Leaves: leavesCopy,
	}
}

// TreeDataFromInclusionProofs creates tree data from inclusion proofs.
func TreeDataFromInclusionProofs(proofs []InclusionProof) *TreeData {
	proofsCopy := make([]InclusionProof, len(proofs))
	copy(proofsCopy, proofs)
	return &TreeData{
		InclusionProofs: proofsCopy,
	}
}

// InclusionProofFromHashes creates an inclusion proof.
func InclusionProofFromHashes(leafIndex, treeSize uint64, hashes []crypto.Hash) InclusionProof {
	hashesCopy := make([]crypto.Hash, len(hashes))
	copy(hashesCopy, hashes)
	return InclusionProof{
		LeafIndex: leafIndex,
		TreeSize:  treeSize,
		Hashes:    hashesCopy,
	}
}

// EvidenceBundleSet represents a collection of related evidence bundles.
// Useful for reporting multiple related anomalies.
type EvidenceBundleSet struct {
	Bundles     []*EvidenceBundle `json:"bundles"`
	CreatedAt   time.Time         `json:"created_at"`
	Description string            `json:"description,omitempty"`
}

// NewEvidenceBundleSet creates a new evidence bundle set.
func NewEvidenceBundleSet(bundles []*EvidenceBundle, description string) *EvidenceBundleSet {
	return &EvidenceBundleSet{
		Bundles:     bundles,
		CreatedAt:   time.Now().UTC(),
		Description: description,
	}
}

// VerifyAll verifies all bundles in the set.
func (ebs *EvidenceBundleSet) VerifyAll(logPubKey *crypto.PublicKey, witnessPubKeys map[crypto.Hash]*crypto.PublicKey) []*types.VerificationResult {
	results := make([]*types.VerificationResult, len(ebs.Bundles))
	for i, bundle := range ebs.Bundles {
		results[i] = bundle.Verify(logPubKey, witnessPubKeys)
	}
	return results
}

// HasValidEvidence returns true if any bundle in the set is valid.
func (ebs *EvidenceBundleSet) HasValidEvidence(logPubKey *crypto.PublicKey, witnessPubKeys map[crypto.Hash]*crypto.PublicKey) bool {
	for _, bundle := range ebs.Bundles {
		if bundle.Verify(logPubKey, witnessPubKeys).Valid {
			return true
		}
	}
	return false
}

// SortBundles sorts bundles by case type, then by creation time.
func (ebs *EvidenceBundleSet) SortBundles() {
	sort.Slice(ebs.Bundles, func(i, j int) bool {
		if ebs.Bundles[i].Case != ebs.Bundles[j].Case {
			return ebs.Bundles[i].Case < ebs.Bundles[j].Case
		}
		return ebs.Bundles[i].CreatedAt.Before(ebs.Bundles[j].CreatedAt)
	})
}

// SerializeDeterministic returns a deterministic binary encoding of the evidence bundle.
// This uses a custom binary format for maximum portability and determinism.
// Format:
//   uint32: format version
//   bytes:  log public key (32 bytes)
//   string: log origin (length-prefixed)
//   uint32: evidence case
//   uint32: number of checkpoints
//   for each checkpoint:
//     bytes:  origin (length-prefixed)
//     uint64: tree size
//     bytes:  root hash (32 bytes)
//     bytes:  log signature (64 bytes)
//     bytes:  key id (4 bytes)
//   uint32: number of cosignatures
//   for each cosignature:
//     bytes:  witness key hash (32 bytes)
//     uint64: tree size
//     bytes:  root hash (32 bytes)
//     bytes:  witness signature (64 bytes)
//   consistency proof (if present):
//     bool:   present
//     uint64: old size
//     uint64: new size
//     uint32: number of hashes
//     for each hash: bytes (32 bytes)
//   tree data (if present):
//     bool:   present
//     uint32: number of leaves
//     for each leaf: bytes (32 bytes)
//     uint32: number of inclusion proofs
//     for each proof:
//       uint64: leaf index
//       uint64: tree size
//       uint32: number of hashes
//       for each hash: bytes (32 bytes)
func (eb *EvidenceBundle) SerializeDeterministic() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Format version
	if err := binary.Write(buf, binary.BigEndian, uint32(eb.FormatVersion)); err != nil {
		return nil, err
	}

	// Log public key (32 bytes)
	buf.Write(eb.LogIdentity.PublicKey[:])

	// Log origin (length-prefixed string)
	originBytes := []byte(eb.LogIdentity.Origin)
	if err := binary.Write(buf, binary.BigEndian, uint32(len(originBytes))); err != nil {
		return nil, err
	}
	buf.Write(originBytes)

	// Evidence case
	if err := binary.Write(buf, binary.BigEndian, uint32(eb.Case)); err != nil {
		return nil, err
	}

	// Checkpoints
	if err := binary.Write(buf, binary.BigEndian, uint32(len(eb.Checkpoints))); err != nil {
		return nil, err
	}
	for _, cp := range eb.Checkpoints {
		// Origin
		originBytes := []byte(cp.Checkpoint.Origin)
		if err := binary.Write(buf, binary.BigEndian, uint32(len(originBytes))); err != nil {
			return nil, err
		}
		buf.Write(originBytes)

		// Tree size
		if err := binary.Write(buf, binary.BigEndian, cp.Checkpoint.SignedTreeHead.Size); err != nil {
			return nil, err
		}

		// Root hash
		buf.Write(cp.Checkpoint.SignedTreeHead.RootHash[:])

		// Log signature
		buf.Write(cp.Checkpoint.SignedTreeHead.Signature[:])

		// Key ID
		buf.Write(cp.Checkpoint.KeyId[:])
	}

	// Cosignatures
	if err := binary.Write(buf, binary.BigEndian, uint32(len(eb.Cosignatures))); err != nil {
		return nil, err
	}
	for _, cosig := range eb.Cosignatures {
		// Witness key hash
		buf.Write(cosig.WitnessID[:])

		// Tree size
		if err := binary.Write(buf, binary.BigEndian, cosig.Cosignature.TreeSize); err != nil {
			return nil, err
		}

		// Root hash
		buf.Write(cosig.Cosignature.RootHash[:])

		// Witness signature
		buf.Write(cosig.Cosignature.Signature[:])
	}

	// Consistency proof
	hasConsistencyProof := eb.ConsistencyProof != nil
	if err := binary.Write(buf, binary.BigEndian, hasConsistencyProof); err != nil {
		return nil, err
	}
	if hasConsistencyProof {
		if err := binary.Write(buf, binary.BigEndian, eb.ConsistencyProof.OldSize); err != nil {
			return nil, err
		}
		if err := binary.Write(buf, binary.BigEndian, eb.ConsistencyProof.NewSize); err != nil {
			return nil, err
		}
		if err := binary.Write(buf, binary.BigEndian, uint32(len(eb.ConsistencyProof.Hashes))); err != nil {
			return nil, err
		}
		for _, h := range eb.ConsistencyProof.Hashes {
			buf.Write(h[:])
		}
	}

	// Tree data
	hasTreeData := eb.TreeData != nil
	if err := binary.Write(buf, binary.BigEndian, hasTreeData); err != nil {
		return nil, err
	}
	if hasTreeData {
		if err := binary.Write(buf, binary.BigEndian, uint32(len(eb.TreeData.Leaves))); err != nil {
			return nil, err
		}
		for _, leaf := range eb.TreeData.Leaves {
			buf.Write(leaf[:])
		}
		if err := binary.Write(buf, binary.BigEndian, uint32(len(eb.TreeData.InclusionProofs))); err != nil {
			return nil, err
		}
		for _, proof := range eb.TreeData.InclusionProofs {
			if err := binary.Write(buf, binary.BigEndian, proof.LeafIndex); err != nil {
				return nil, err
			}
			if err := binary.Write(buf, binary.BigEndian, proof.TreeSize); err != nil {
				return nil, err
			}
			if err := binary.Write(buf, binary.BigEndian, uint32(len(proof.Hashes))); err != nil {
				return nil, err
			}
			for _, h := range proof.Hashes {
				buf.Write(h[:])
			}
		}
	}

	return buf.Bytes(), nil
}

// DeserializeDeterministic parses an evidence bundle from deterministic binary format.
func DeserializeDeterministic(data []byte) (*EvidenceBundle, error) {
	buf := bytes.NewReader(data)
	eb := &EvidenceBundle{}

	// Format version
	var formatVersion uint32
	if err := binary.Read(buf, binary.BigEndian, &formatVersion); err != nil {
		return nil, err
	}
	eb.FormatVersion = int(formatVersion)

	// Log public key
	var pubKey crypto.PublicKey
	if _, err := io.ReadFull(buf, pubKey[:]); err != nil {
		return nil, err
	}
	eb.LogIdentity.PublicKey = pubKey

	// Log origin
	var originLen uint32
	if err := binary.Read(buf, binary.BigEndian, &originLen); err != nil {
		return nil, err
	}
	originBytes := make([]byte, originLen)
	if _, err := io.ReadFull(buf, originBytes); err != nil {
		return nil, err
	}
	eb.LogIdentity.Origin = string(originBytes)

	// Evidence case
	var caseVal uint32
	if err := binary.Read(buf, binary.BigEndian, &caseVal); err != nil {
		return nil, err
	}
	eb.Case = EvidenceCase(caseVal)

	// Checkpoints
	var numCheckpoints uint32
	if err := binary.Read(buf, binary.BigEndian, &numCheckpoints); err != nil {
		return nil, err
	}
	eb.Checkpoints = make([]*types.Checkpoint, numCheckpoints)
	for i := uint32(0); i < numCheckpoints; i++ {
		cp := &checkpoint.Checkpoint{}
		wrapped := &types.Checkpoint{Checkpoint: cp}

		// Origin
		var cpOriginLen uint32
		if err := binary.Read(buf, binary.BigEndian, &cpOriginLen); err != nil {
			return nil, err
		}
		cpOriginBytes := make([]byte, cpOriginLen)
		if _, err := io.ReadFull(buf, cpOriginBytes); err != nil {
			return nil, err
		}
		cp.Origin = string(cpOriginBytes)

		// Tree size
		if err := binary.Read(buf, binary.BigEndian, &cp.SignedTreeHead.Size); err != nil {
			return nil, err
		}

		// Root hash
		if _, err := io.ReadFull(buf, cp.SignedTreeHead.RootHash[:]); err != nil {
			return nil, err
		}

		// Log signature
		if _, err := io.ReadFull(buf, cp.SignedTreeHead.Signature[:]); err != nil {
			return nil, err
		}

		// Key ID
		if _, err := io.ReadFull(buf, cp.KeyId[:]); err != nil {
			return nil, err
		}

		wrapped.LogID = pubKey.Hash()
		eb.Checkpoints[i] = wrapped
	}

	// Cosignatures
	var numCosignatures uint32
	if err := binary.Read(buf, binary.BigEndian, &numCosignatures); err != nil {
		return nil, err
	}
	eb.Cosignatures = make([]types.Cosignature, numCosignatures)
	for i := uint32(0); i < numCosignatures; i++ {
		var cosig types.Cosignature

		// Witness key hash
		if _, err := io.ReadFull(buf, cosig.WitnessID[:]); err != nil {
			return nil, err
		}

		// Tree size
		if err := binary.Read(buf, binary.BigEndian, &cosig.Cosignature.TreeSize); err != nil {
			return nil, err
		}

		// Root hash
		if _, err := io.ReadFull(buf, cosig.Cosignature.RootHash[:]); err != nil {
			return nil, err
		}

		// Witness signature
		if _, err := io.ReadFull(buf, cosig.Cosignature.Signature[:]); err != nil {
			return nil, err
		}

		eb.Cosignatures[i] = cosig
	}

	// Consistency proof
	var hasConsistencyProof bool
	if err := binary.Read(buf, binary.BigEndian, &hasConsistencyProof); err != nil {
		return nil, err
	}
	if hasConsistencyProof {
		proof := &ConsistencyProof{}
		if err := binary.Read(buf, binary.BigEndian, &proof.OldSize); err != nil {
			return nil, err
		}
		if err := binary.Read(buf, binary.BigEndian, &proof.NewSize); err != nil {
			return nil, err
		}
		var numHashes uint32
		if err := binary.Read(buf, binary.BigEndian, &numHashes); err != nil {
			return nil, err
		}
		proof.Hashes = make([]crypto.Hash, numHashes)
		for i := uint32(0); i < numHashes; i++ {
			if _, err := io.ReadFull(buf, proof.Hashes[i][:]); err != nil {
				return nil, err
			}
		}
		eb.ConsistencyProof = proof
	}

	// Tree data
	var hasTreeData bool
	if err := binary.Read(buf, binary.BigEndian, &hasTreeData); err != nil {
		return nil, err
	}
	if hasTreeData {
		data := &TreeData{}
		var numLeaves uint32
		if err := binary.Read(buf, binary.BigEndian, &numLeaves); err != nil {
			return nil, err
		}
		data.Leaves = make([]crypto.Hash, numLeaves)
		for i := uint32(0); i < numLeaves; i++ {
			if _, err := io.ReadFull(buf, data.Leaves[i][:]); err != nil {
				return nil, err
			}
		}
		var numProofs uint32
		if err := binary.Read(buf, binary.BigEndian, &numProofs); err != nil {
			return nil, err
		}
		data.InclusionProofs = make([]InclusionProof, numProofs)
		for i := uint32(0); i < numProofs; i++ {
			var proof InclusionProof
			if err := binary.Read(buf, binary.BigEndian, &proof.LeafIndex); err != nil {
				return nil, err
			}
			if err := binary.Read(buf, binary.BigEndian, &proof.TreeSize); err != nil {
				return nil, err
			}
			var numHashes uint32
			if err := binary.Read(buf, binary.BigEndian, &numHashes); err != nil {
				return nil, err
			}
			proof.Hashes = make([]crypto.Hash, numHashes)
			for j := uint32(0); j < numHashes; j++ {
				if _, err := io.ReadFull(buf, proof.Hashes[j][:]); err != nil {
					return nil, err
				}
			}
			data.InclusionProofs[i] = proof
		}
		eb.TreeData = data
	}

	return eb, nil
}

// HexEncode returns a hex-encoded string of the deterministic binary serialization.
func (eb *EvidenceBundle) HexEncode() (string, error) {
	data, err := eb.SerializeDeterministic()
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(data), nil
}

// HexDecode parses an evidence bundle from a hex-encoded deterministic binary string.
func HexDecode(hexStr string) (*EvidenceBundle, error) {
	data, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, err
	}
	return DeserializeDeterministic(data)
}