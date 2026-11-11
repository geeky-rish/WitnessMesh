// Package types defines the core data structures for WitnessMesh.
package types

import (
	"encoding/base64"
	"fmt"
	"io"
	"time"

	"sigsum.org/sigsum-go/pkg/ascii"
	"sigsum.org/sigsum-go/pkg/checkpoint"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/types"
)

// LogIdentity represents a transparency log's identity
type LogIdentity struct {
	PublicKey crypto.PublicKey
	Origin    string // The checkpoint origin string
}

// WitnessIdentity represents a witness's identity
type WitnessIdentity struct {
	Name       string
	PublicKey  crypto.PublicKey
	URL        string
	KeyHash    crypto.Hash
}

// Checkpoint wraps the sigsum checkpoint with additional metadata
type Checkpoint struct {
	*checkpoint.Checkpoint
	LogID       crypto.Hash
	ReceivedAt  time.Time
	Source      string // "log" or "witness"
}

// Cosignature wraps the sigsum cosignature with witness identity
type Cosignature struct {
	*checkpoint.CosignatureLine
	WitnessID crypto.Hash
	Verified  bool
	VerifiedAt time.Time
}

// CosignedCheckpoint represents a checkpoint with witness cosignatures
type CosignedCheckpoint struct {
	Checkpoint     *Checkpoint
	Cosignatures   []Cosignature
	QuorumMet      bool
	VerifiedAt     time.Time
}

// EvidenceBundle represents a cryptographic evidence bundle
type EvidenceBundle struct {
	Version        int
	LogIdentity    LogIdentity
	Case           EvidenceCase
	Checkpoints    []*Checkpoint
	Cosignatures   []Cosignature
	ConsistencyProof *ConsistencyProof
	DetectionTime  time.Time
	DetectorID     string
	Metadata       map[string]string
}

// EvidenceCase represents the type of evidence
type EvidenceCase int

const (
	EvidenceCaseSameSizeFork EvidenceCase = iota + 1
	EvidenceCaseDifferentSizeFork
	EvidenceCaseWitnessEquivocation
)

// ConsistencyProof represents a Merkle consistency proof
type ConsistencyProof struct {
	OldSize   uint64
	NewSize   uint64
	Hashes    []crypto.Hash
}

// VerificationResult represents the result of evidence verification
type VerificationResult struct {
	Valid       bool
	Case        EvidenceCase
	Description string
	Errors      []string
}

// Incident represents a detected security incident
type Incident struct {
	ID           string
	Type         IncidentType
	Severity     IncidentSeverity
	Timestamp    time.Time
	LogID        crypto.Hash
	Evidence     *EvidenceBundle
	Description  string
	Acknowledged bool
	ResolvedAt   *time.Time
}

// IncidentType represents the type of incident
type IncidentType int

const (
	IncidentTypeLogFork IncidentType = iota + 1
	IncidentTypeWitnessEquivocation
	IncidentTypeMissingCheckpoint
	IncidentTypeStaleCheckpoint
	IncidentTypeNetworkFailure
)

// IncidentSeverity represents the severity of an incident
type IncidentSeverity int

const (
	IncidentSeverityCritical IncidentSeverity = iota + 1
	IncidentSeverityHigh
	IncidentSeverityMedium
	IncidentSeverityLow
)

// QuorumPolicy represents the trust policy configuration
type QuorumPolicy struct {
	Logs      map[crypto.Hash]LogIdentity
	Witnesses map[crypto.Hash]WitnessIdentity
	Quorum    QuorumTree
}

// QuorumTree represents the quorum policy tree
type QuorumTree interface {
	Evaluate(verified map[crypto.Hash]bool) bool
}

// KOfNQuorum represents a simple k-of-n quorum
type KOfNQuorum struct {
	K             int
	WitnessHashes []crypto.Hash
}

// Evaluate implements QuorumTree.Evaluate
func (q *KOfNQuorum) Evaluate(verified map[crypto.Hash]bool) bool {
	count := 0
	for _, h := range q.WitnessHashes {
		if verified[h] {
			count++
		}
	}
	return count >= q.K
}

// WriteCheckpoint writes a checkpoint to ASCII format
func WriteCheckpoint(w io.Writer, cp *Checkpoint) error {
	return cp.Checkpoint.ToASCII(w)
}

// ParseCheckpoint parses a checkpoint from ASCII format
func ParseCheckpoint(r io.Reader) (*Checkpoint, error) {
	cp := &checkpoint.Checkpoint{}
	if err := cp.FromASCII(r); err != nil {
		return nil, err
	}
	return &Checkpoint{
		Checkpoint: cp,
		ReceivedAt: time.Now(),
	}, nil
}

// VerifyCheckpoint verifies a checkpoint's signature
func VerifyCheckpoint(cp *Checkpoint, pubKey *crypto.PublicKey) error {
	return cp.Checkpoint.Verify(pubKey)
}

// KeyIdFromPublicKey derives a key ID from a public key and name
func KeyIdFromPublicKey(name string, pubKey *crypto.PublicKey) string {
	keyHash := pubKey.Hash()
	return fmt.Sprintf("%x", keyHash[:4])
}

// NewLogIdentity creates a new LogIdentity from a public key
func NewLogIdentity(pubKey *crypto.PublicKey) *LogIdentity {
	origin := types.SigsumCheckpointOrigin(pubKey)
	keyHash := pubKey.Hash()
	return &LogIdentity{
		PublicKey: *pubKey,
		Origin:    origin,
	}
}

// NewWitnessIdentity creates a new WitnessIdentity
func NewWitnessIdentity(name string, pubKey *crypto.PublicKey, url string) *WitnessIdentity {
	keyHash := pubKey.Hash()
	return &WitnessIdentity{
		Name:      name,
		PublicKey: *pubKey,
		URL:       url,
		KeyHash:   keyHash,
	}
}

// HashFromBase64 decodes a base64 hash
func HashFromBase64(s string) (crypto.Hash, error) {
	return crypto.HashFromBase64(s)
}

// HashToBase64 encodes a hash to base64
func HashToBase64(h crypto.Hash) string {
	return base64.StdEncoding.EncodeToString(h[:])
}

// SignatureFromBase64 decodes a base64 signature
func SignatureFromBase64(s string) (crypto.Signature, error) {
	return crypto.SignatureFromBase64(s)
}

// SignatureToBase64 encodes a signature to base64
func SignatureToBase64(sig crypto.Signature) string {
	return base64.StdEncoding.EncodeToString(sig[:])
}

// VerifyCosignature verifies a witness cosignature
func VerifyCosignature(cp *Checkpoint, cosig *Cosignature, witnessPubKey *crypto.PublicKey) bool {
	return cp.Checkpoint.VerifyCosignature(witnessPubKey, &cosig.Cosignature)
}

// FormatCheckpoint formats a checkpoint for signing
func FormatCheckpoint(origin string, size uint64, rootHash crypto.Hash) string {
	return fmt.Sprintf("%s\n%d\n%s\n",
		origin, size,
		base64.StdEncoding.EncodeToString(rootHash[:]))
}

// ParseASCIICheckpoint parses a checkpoint from ASCII
func ParseASCIICheckpoint(r io.Reader) (*Checkpoint, error) {
	cp := &checkpoint.Checkpoint{}
	p := ascii.NewLineReader(r)
	if err := cp.Parse(&p); err != nil {
		return nil, err
	}
	return &Checkpoint{
		Checkpoint: cp,
		ReceivedAt: time.Now(),
	}, nil
}