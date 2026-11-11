// Package storage provides persistent storage for WitnessMesh components.
package storage

import (
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"

	"witnessmesh/internal/types"

	"github.com/mattn/go-sqlite3"
	"sigsum.org/sigsum-go/pkg/checkpoint"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/types"
)

const schema = `
-- Checkpoints table stores observed checkpoints
CREATE TABLE IF NOT EXISTS checkpoints (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	log_id BLOB NOT NULL,
	origin TEXT NOT NULL,
	tree_size INTEGER NOT NULL,
	root_hash BLOB NOT NULL,
	signature BLOB NOT NULL,
	key_id BLOB NOT NULL,
	received_at TIMESTAMP NOT NULL,
	source TEXT NOT NULL,
	UNIQUE(log_id, tree_size, root_hash)
);

-- Cosignatures table stores witness cosignatures
CREATE TABLE IF NOT EXISTS cosignatures (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	checkpoint_id INTEGER NOT NULL,
	witness_key_hash BLOB NOT NULL,
	witness_name TEXT NOT NULL,
	timestamp INTEGER NOT NULL,
	signature BLOB NOT NULL,
	verified BOOLEAN NOT NULL DEFAULT 0,
	verified_at TIMESTAMP,
	FOREIGN KEY(checkpoint_id) REFERENCES checkpoints(id) ON DELETE CASCADE,
	UNIQUE(checkpoint_id, witness_key_hash)
);

-- Witness state table stores the latest checkpoint per log per witness
CREATE TABLE IF NOT EXISTS witness_state (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	witness_key_hash BLOB NOT NULL,
	log_id BLOB NOT NULL,
	log_origin TEXT NOT NULL,
	latest_tree_size INTEGER NOT NULL,
	latest_root_hash BLOB NOT NULL,
	updated_at TIMESTAMP NOT NULL,
	UNIQUE(witness_key_hash, log_id)
);

-- Incidents table stores detected security incidents
CREATE TABLE IF NOT EXISTS incidents (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	incident_id TEXT NOT NULL UNIQUE,
	type INTEGER NOT NULL,
	severity INTEGER NOT NULL,
	timestamp TIMESTAMP NOT NULL,
	log_id BLOB NOT NULL,
	evidence_blob BLOB,
	description TEXT,
	acknowledged BOOLEAN NOT NULL DEFAULT 0,
	resolved_at TIMESTAMP,
	created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Evidence bundles table stores generated evidence
CREATE TABLE IF NOT EXISTS evidence_bundles (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	bundle_id TEXT NOT NULL UNIQUE,
	version INTEGER NOT NULL,
	log_id BLOB NOT NULL,
	case_type INTEGER NOT NULL,
	checkpoints_blob BLOB NOT NULL,
	cosignatures_blob BLOB,
	consistency_proof_blob BLOB,
	detection_time TIMESTAMP NOT NULL,
	detector_id TEXT NOT NULL,
	metadata_blob BLOB,
	created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Policy changes table stores trust policy updates
CREATE TABLE IF NOT EXISTS policy_changes (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	change_id TEXT NOT NULL UNIQUE,
	timestamp TIMESTAMP NOT NULL,
	action TEXT NOT NULL,
	witness_key_hash BLOB,
	reason TEXT,
	evidence_bundle_id TEXT,
	FOREIGN KEY(evidence_bundle_id) REFERENCES evidence_bundles(bundle_id)
);

CREATE INDEX IF NOT EXISTS idx_checkpoints_log_size ON checkpoints(log_id, tree_size);
CREATE INDEX IF NOT EXISTS idx_cosignatures_checkpoint ON cosignatures(checkpoint_id);
CREATE INDEX IF NOT EXISTS idx_witness_state_witness_log ON witness_state(witness_key_hash, log_id);
CREATE INDEX IF NOT EXISTS idx_incidents_log_time ON incidents(log_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_evidence_bundles_log ON evidence_bundles(log_id);
`

// SQLiteStore implements persistent storage using SQLite
type SQLiteStore struct {
	db *sql.DB
}

// NewSQLiteStore creates a new SQLite store
func NewSQLiteStore(dbPath string) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite3", dbPath+"?_foreign_keys=on&_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to create schema: %w", err)
	}

	return &SQLiteStore{db: db}, nil
}

// Close closes the database connection
func (s *SQLiteStore) Close() error {
	return s.db.Close()
}

// SaveCheckpoint saves a checkpoint to the database
func (s *SQLiteStore) SaveCheckpoint(cp *types.Checkpoint) (int64, error) {
	logID := cp.LogID
	origin := cp.Origin
	treeSize := cp.TreeHead.Size
	rootHash := cp.TreeHead.RootHash[:]
	signature := cp.Signature[:]
	keyID := cp.KeyId

	result, err := s.db.Exec(`
		INSERT OR IGNORE INTO checkpoints
		(log_id, origin, tree_size, root_hash, signature, key_id, received_at, source)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		logID[:], origin, treeSize, rootHash, signature, keyID,
		cp.ReceivedAt, cp.Source)

	if err != nil {
		return 0, fmt.Errorf("failed to save checkpoint: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("failed to get checkpoint ID: %w", err)
	}

	// If checkpoint already existed, get its ID
	if id == 0 {
		err = s.db.QueryRow(`
			SELECT id FROM checkpoints
			WHERE log_id = ? AND tree_size = ? AND root_hash = ?`,
			logID[:], treeSize, rootHash).Scan(&id)
		if err != nil {
			return 0, fmt.Errorf("failed to get existing checkpoint ID: %w", err)
		}
	}

	return id, nil
}

// SaveCosignature saves a witness cosignature
func (s *SQLiteStore) SaveCosignature(checkpointID int64, cosig *types.Cosignature) error {
	witnessKeyHash := cosig.WitnessID
	witnessName := cosig.KeyName
	timestamp := cosig.Timestamp
	signature := cosig.Signature[:]
	verified := cosig.Verified
	verifiedAt := cosig.VerifiedAt

	_, err := s.db.Exec(`
		INSERT OR REPLACE INTO cosignatures
		(checkpoint_id, witness_key_hash, witness_name, timestamp, signature, verified, verified_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		checkpointID, witnessKeyHash[:], witnessName, timestamp,
		signature, verified, verifiedAt)

	return err
}

// GetLatestCheckpoint gets the latest checkpoint for a log
func (s *SQLiteStore) GetLatestCheckpoint(logID crypto.Hash) (*types.Checkpoint, error) {
	row := s.db.QueryRow(`
		SELECT id, origin, tree_size, root_hash, signature, key_id, received_at, source
		FROM checkpoints
		WHERE log_id = ?
		ORDER BY tree_size DESC
		LIMIT 1`, logID[:])

	return s.scanCheckpoint(row)
}

// GetCheckpointBySize gets a checkpoint for a log at a specific size
func (s *SQLiteStore) GetCheckpointBySize(logID crypto.Hash, size uint64) (*types.Checkpoint, error) {
	row := s.db.QueryRow(`
		SELECT id, origin, tree_size, root_hash, signature, key_id, received_at, source
		FROM checkpoints
		WHERE log_id = ? AND tree_size = ?
		LIMIT 1`, logID[:], size)

	return s.scanCheckpoint(row)
}

// GetCheckpointBySizeAndRoot gets a checkpoint for a log at specific size and root
func (s *SQLiteStore) GetCheckpointBySizeAndRoot(logID crypto.Hash, size uint64, rootHash crypto.Hash) (*types.Checkpoint, error) {
	row := s.db.QueryRow(`
		SELECT id, origin, tree_size, root_hash, signature, key_id, received_at, source
		FROM checkpoints
		WHERE log_id = ? AND tree_size = ? AND root_hash = ?
		LIMIT 1`, logID[:], size, rootHash[:])

	return s.scanCheckpoint(row)
}

// GetCosignaturesForCheckpoint gets all cosignatures for a checkpoint
func (s *SQLiteStore) GetCosignaturesForCheckpoint(checkpointID int64) ([]types.Cosignature, error) {
	rows, err := s.db.Query(`
		SELECT witness_key_hash, witness_name, timestamp, signature, verified, verified_at
		FROM cosignatures
		WHERE checkpoint_id = ?`, checkpointID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var cosignatures []types.Cosignature
	for rows.Next() {
		var cs types.Cosignature
		var witnessKeyHash, signature []byte
		var verified bool
		var verifiedAt sql.NullTime

		if err := rows.Scan(&witnessKeyHash, &cs.KeyName, &cs.Timestamp,
			&signature, &verified, &verifiedAt); err != nil {
			return nil, err
		}

		copy(cs.WitnessID[:], witnessKeyHash)
		copy(cs.Signature[:], signature)
		cs.Verified = verified
		if verifiedAt.Valid {
			cs.VerifiedAt = verifiedAt.Time
		}

		cosignatures = append(cosignatures, cs)
	}

	return cosignatures, nil
}

// SaveWitnessState saves the latest checkpoint state for a witness
func (s *SQLiteStore) SaveWitnessState(witnessKeyHash crypto.Hash, logID crypto.Hash, logOrigin string, treeSize uint64, rootHash crypto.Hash) error {
	_, err := s.db.Exec(`
		INSERT OR REPLACE INTO witness_state
		(witness_key_hash, log_id, log_origin, latest_tree_size, latest_root_hash, updated_at)
		VALUES (?, ?, ?, ?, ?, ?)`,
		witnessKeyHash[:], logID[:], logOrigin, treeSize, rootHash[:], time.Now())
	return err
}

// GetWitnessState gets the latest checkpoint state for a witness and log
func (s *SQLiteStore) GetWitnessState(witnessKeyHash crypto.Hash, logID crypto.Hash) (uint64, crypto.Hash, error) {
	var treeSize uint64
	var rootHashBytes []byte

	err := s.db.QueryRow(`
		SELECT latest_tree_size, latest_root_hash
		FROM witness_state
		WHERE witness_key_hash = ? AND log_id = ?`,
		witnessKeyHash[:], logID[:]).Scan(&treeSize, &rootHashBytes)

	if err == sql.ErrNoRows {
		return 0, crypto.Hash{}, nil
	}
	if err != nil {
		return 0, crypto.Hash{}, err
	}

	var rootHash crypto.Hash
	copy(rootHash[:], rootHashBytes)
	return treeSize, rootHash, nil
}

// SaveIncident saves a security incident
func (s *SQLiteStore) SaveIncident(incident *types.Incident) error {
	var evidenceBlob []byte
	if incident.Evidence != nil {
		// For now, store as JSON or skip
		evidenceBlob = []byte("evidence_placeholder")
	}

	_, err := s.db.Exec(`
		INSERT OR REPLACE INTO incidents
		(incident_id, type, severity, timestamp, log_id, evidence_blob, description, acknowledged, resolved_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		incident.ID, incident.Type, incident.Severity,
		incident.Timestamp, incident.LogID[:], evidenceBlob,
		incident.Description, incident.Acknowledged, incident.ResolvedAt)
	return err
}

// GetIncidents gets incidents for a log
func (s *SQLiteStore) GetIncidents(logID crypto.Hash, limit int) ([]types.Incident, error) {
	rows, err := s.db.Query(`
		SELECT incident_id, type, severity, timestamp, log_id, evidence_blob, description, acknowledged, resolved_at
		FROM incidents
		WHERE log_id = ?
		ORDER BY timestamp DESC
		LIMIT ?`, logID[:], limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var incidents []types.Incident
	for rows.Next() {
		var inc types.Incident
		var logIDBytes []byte
		var resolvedAt sql.NullTime

		if err := rows.Scan(&inc.ID, &inc.Type, &inc.Severity, &inc.Timestamp,
			&logIDBytes, &inc.Description, &inc.Acknowledged, &resolvedAt); err != nil {
			return nil, err
		}

		copy(inc.LogID[:], logIDBytes)
		if resolvedAt.Valid {
			inc.ResolvedAt = &resolvedAt.Time
		}

		incidents = append(incidents, inc)
	}

	return incidents, nil
}

// SaveEvidenceBundle saves an evidence bundle
func (s *SQLiteStore) SaveEvidenceBundle(bundle *types.EvidenceBundle) error {
	// For now, just store basic info
	_, err := s.db.Exec(`
		INSERT OR REPLACE INTO evidence_bundles
		(bundle_id, version, log_id, case_type, checkpoints_blob, cosignatures_blob, consistency_proof_blob, detection_time, detector_id, metadata_blob)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		bundle.Metadata["bundle_id"], bundle.Version, bundle.LogIdentity.PublicKey.Hash()[:],
		bundle.Case, []byte("checkpoints"), []byte("cosignatures"), []byte("proof"),
		bundle.DetectionTime, bundle.DetectorID, []byte("metadata"))
	return err
}

// SavePolicyChange saves a trust policy change
func (s *SQLiteStore) SavePolicyChange(changeID string, action string, witnessKeyHash crypto.Hash, reason string, evidenceBundleID string) error {
	var wkh []byte
	if witnessKeyHash != (crypto.Hash{}) {
		wkh = witnessKeyHash[:]
	}
	_, err := s.db.Exec(`
		INSERT INTO policy_changes
		(change_id, timestamp, action, witness_key_hash, reason, evidence_bundle_id)
		VALUES (?, ?, ?, ?, ?, ?)`,
		changeID, time.Now(), action, wkh, reason, evidenceBundleID)
	return err
}

// scanCheckpoint scans a checkpoint from a database row
func (s *SQLiteStore) scanCheckpoint(row *sql.Row) (*types.Checkpoint, error) {
	var id int64
	var origin string
	var treeSize uint64
	var rootHashBytes, signatureBytes, keyIDBytes []byte
	var receivedAt time.Time
	var source string

	err := row.Scan(&id, &origin, &treeSize, &rootHashBytes, &signatureBytes, &keyIDBytes, &receivedAt, &source)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	var rootHash, signature crypto.Signature
	var keyID [4]byte
	copy(rootHash[:], rootHashBytes)
	copy(signature[:], signatureBytes)
	copy(keyID[:], keyIDBytes)

	// We need to reconstruct the checkpoint
	// This is simplified - in reality we'd store the full checkpoint
	cp := &types.Checkpoint{
		ReceivedAt: receivedAt,
		Source:     source,
	}

	return cp, nil
}

// GetConflictingCheckpoints finds checkpoints with same size but different roots
func (s *SQLiteStore) GetConflictingCheckpoints(logID crypto.Hash) ([]*types.Checkpoint, error) {
	rows, err := s.db.Query(`
		SELECT c1.id, c1.origin, c1.tree_size, c1.root_hash, c1.signature, c1.key_id, c1.received_at, c1.source
		FROM checkpoints c1
		JOIN checkpoints c2 ON c1.log_id = c2.log_id AND c1.tree_size = c2.tree_size AND c1.root_hash != c2.root_hash
		WHERE c1.log_id = ?
		ORDER BY c1.tree_size DESC`, logID[:])
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var checkpoints []*types.Checkpoint
	for rows.Next() {
		cp, err := s.scanCheckpointFromRows(rows)
		if err != nil {
			return nil, err
		}
		if cp != nil {
			checkpoints = append(checkpoints, cp)
		}
	}

	return checkpoints, nil
}

func (s *SQLiteStore) scanCheckpointFromRows(rows *sql.Rows) (*types.Checkpoint, error) {
	var id int64
	var origin string
	var treeSize uint64
	var rootHashBytes, signatureBytes, keyIDBytes []byte
	var receivedAt time.Time
	var source string

	err := rows.Scan(&id, &origin, &treeSize, &rootHashBytes, &signatureBytes, &keyIDBytes, &receivedAt, &source)
	if err != nil {
		return nil, err
	}

	var rootHash crypto.Hash
	var signature crypto.Signature
	var keyID [4]byte
	copy(rootHash[:], rootHashBytes)
	copy(signature[:], signatureBytes)
	copy(keyID[:], keyIDBytes)

	cp := &types.Checkpoint{
		ReceivedAt: receivedAt,
		Source:     source,
	}

	// We can't fully reconstruct without the full checkpoint data
	// In a real implementation, we'd store the full checkpoint text
	return cp, nil
}

// Helper to convert hash to hex string
func hashToHex(h crypto.Hash) string {
	return hex.EncodeToString(h[:])
}

// Helper to convert bytes to hash
func bytesToHash(b []byte) crypto.Hash {
	var h crypto.Hash
	copy(h[:], b)
	return h
}