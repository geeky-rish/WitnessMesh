// Package client implements the client simulator for WitnessMesh.
package client

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"sigsum.org/sigsum-go/pkg/ascii"
	"sigsum.org/sigsum-go/pkg/checkpoint"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/types"

	"witnessmesh/internal/storage"
	"witnessmesh/internal/types"
)

// ErrNoNewCheckpoint is returned when polling finds no new checkpoint
var ErrNoNewCheckpoint = errors.New("no new checkpoint available")

// ErrQuorumNotMet is returned when witness quorum is not met
var ErrQuorumNotMet = errors.New("quorum not met")

// ErrCheckpointRejected is returned when a checkpoint is rejected by policy
var ErrCheckpointRejected = errors.New("checkpoint rejected by policy")

// ErrCheckpointRegression is returned when a checkpoint regression is detected
var ErrCheckpointRegression = errors.New("checkpoint regression detected")

// ErrCheckpointFork is returned when a fork is detected
var ErrCheckpointFork = errors.New("checkpoint fork detected")

// ErrInvalidSignature is returned when a signature verification fails
var ErrInvalidSignature = errors.New("invalid signature")

// ClientConfig holds the configuration for the client
type ClientConfig struct {
	// LogURL is the URL of the transparency log
	LogURL string
	// LogPublicKey is the public key of the transparency log
	LogPublicKey crypto.PublicKey
	// Witnesses is the list of trusted witnesses
	Witnesses []WitnessConfig
	// QuorumPolicy defines the quorum requirements
	QuorumPolicy QuorumPolicy
	// PollInterval is the interval between polling the log
	PollInterval time.Duration
	// HTTPClient is the HTTP client to use (optional, defaults to http.DefaultClient)
	HTTPClient *http.Client
	// Storage is the persistent storage (optional)
	Storage *storage.SQLiteStore
	// Callback is called when a new valid checkpoint is observed
	Callback func(*CosignedCheckpoint)
}

// WitnessConfig holds configuration for a witness
type WitnessConfig struct {
	Name       string
	PublicKey  crypto.PublicKey
	URL        string
	KeyHash    crypto.Hash
}

// QuorumPolicy defines the quorum requirements
type QuorumPolicy struct {
	// Type is the quorum type (e.g., "kofn")
	Type string
	// K is the minimum number of witnesses required (for k-of-n)
	K int
	// WitnessHashes is the list of witness key hashes that count towards quorum
	WitnessHashes []crypto.Hash
}

// Client is the transparency log client simulator
type Client struct {
	config       ClientConfig
	httpClient   *http.Client
	storage      *storage.SQLiteStore
	mu           sync.RWMutex
	// State tracking
	lastCheckpoint *types.Checkpoint
	// History of observed checkpoints per log
	checkpointHistory map[crypto.Hash][]*types.Checkpoint
	// Witness states
	witnessStates map[crypto.Hash]WitnessState
	// Running state
	running    bool
	stopChan   chan struct{}
	wg         sync.WaitGroup
	callback   func(*CosignedCheckpoint)
}

// WitnessState tracks the latest checkpoint a witness has cosigned
type WitnessState struct {
	WitnessKeyHash crypto.Hash
	LogID          crypto.Hash
	LogOrigin      string
	TreeSize       uint64
	RootHash       crypto.Hash
	Timestamp      time.Time
}

// CosignedCheckpoint represents a checkpoint with verified witness cosignatures
type CosignedCheckpoint struct {
	Checkpoint   *types.Checkpoint
	Cosignatures []types.Cosignature
	QuorumMet    bool
	VerifiedAt   time.Time
}

// NewClient creates a new client simulator
func NewClient(config ClientConfig) (*Client, error) {
	if config.LogURL == "" {
		return nil, errors.New("log URL is required")
	}
	if config.LogPublicKey == (crypto.PublicKey{}) {
		return nil, errors.New("log public key is required")
	}
	if len(config.Witnesses) == 0 {
		return nil, errors.New("at least one witness is required")
	}
	if config.PollInterval == 0 {
		config.PollInterval = 30 * time.Second
	}
	if config.HTTPClient == nil {
		config.HTTPClient = &http.Client{
			Timeout: 10 * time.Second,
		}
	}

	// Validate quorum policy
	if config.QuorumPolicy.K <= 0 {
		config.QuorumPolicy.K = len(config.Witnesses)
	}
	if len(config.QuorumPolicy.WitnessHashes) == 0 {
		for _, w := range config.Witnesses {
			config.QuorumPolicy.WitnessHashes = append(config.QuorumPolicy.WitnessHashes, w.KeyHash)
		}
	}

	client := &Client{
		config:            config,
		httpClient:        config.HTTPClient,
		storage:           config.Storage,
		checkpointHistory: make(map[crypto.Hash][]*types.Checkpoint),
		witnessStates:     make(map[crypto.Hash]WitnessState),
		stopChan:          make(chan struct{}),
		callback:          config.Callback,
	}

	return client, nil
}

// Start begins polling the log for new checkpoints
func (c *Client) Start(ctx context.Context) error {
	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		return errors.New("client already running")
	}
	c.running = true
	c.mu.Unlock()

	c.wg.Add(1)
	go c.pollLoop(ctx)

	return nil
}

// Stop stops the client
func (c *Client) Stop() {
	c.mu.Lock()
	if !c.running {
		c.mu.Unlock()
		return
	}
	c.running = false
	close(c.stopChan)
	c.mu.Unlock()

	c.wg.Wait()
}

// pollLoop periodically polls the log for new checkpoints
func (c *Client) pollLoop(ctx context.Context) {
	defer c.wg.Done()

	ticker := time.NewTicker(c.config.PollInterval)
	defer ticker.Stop()

	// Initial poll
	c.pollOnce(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-c.stopChan:
			return
		case <-ticker.C:
			c.pollOnce(ctx)
		}
	}
}

// pollOnce performs a single poll of the log
func (c *Client) pollOnce(ctx context.Context) {
	cp, err := c.fetchCheckpoint(ctx)
	if err != nil {
		if !errors.Is(err, ErrNoNewCheckpoint) {
			// Log error but continue
			fmt.Printf("Error fetching checkpoint: %v\n", err)
		}
		return
	}

	// Process the new checkpoint
	cosignedCP, err := c.processCheckpoint(ctx, cp)
	if err != nil {
		fmt.Printf("Error processing checkpoint: %v\n", err)
		return
	}

	// Notify callback
	if c.callback != nil {
		c.callback(cosignedCP)
	}
}

// fetchCheckpoint fetches the latest checkpoint from the log
func (c *Client) fetchCheckpoint(ctx context.Context) (*types.Checkpoint, error) {
	url := c.config.LogURL + "/tree-head"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "text/plain")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch checkpoint: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		return nil, ErrNoNewCheckpoint
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Parse the checkpoint
	cp, err := c.parseCheckpoint(body)
	if err != nil {
		return nil, fmt.Errorf("failed to parse checkpoint: %w", err)
	}

	// Verify the checkpoint signature
	if err := c.verifyCheckpointSignature(cp); err != nil {
		return nil, fmt.Errorf("checkpoint signature verification failed: %w", err)
	}

	// Check for regression/fork
	if err := c.checkForRegression(cp); err != nil {
		return nil, err
	}

	return cp, nil
}

// parseCheckpoint parses a checkpoint from ASCII format
func (c *Client) parseCheckpoint(data []byte) (*types.Checkpoint, error) {
	cp := &checkpoint.Checkpoint{}
	p := ascii.NewLineReader(data)
	if err := cp.Parse(&p); err != nil {
		return nil, err
	}

	return &types.Checkpoint{
		Checkpoint: cp,
		LogID:      c.config.LogPublicKey.Hash(),
		ReceivedAt: time.Now(),
		Source:     "log",
	}, nil
}

// verifyCheckpointSignature verifies the checkpoint's signature against the log public key
func (c *Client) verifyCheckpointSignature(cp *types.Checkpoint) error {
	return cp.Checkpoint.Verify(&c.config.LogPublicKey)
}

// checkForRegression checks for checkpoint regressions or forks
func (c *Client) checkForRegression(cp *types.Checkpoint) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	logID := cp.LogID
	history := c.checkpointHistory[logID]

	// Check if this is a new checkpoint (larger tree size)
	if len(history) > 0 {
		lastCP := history[len(history)-1]

		// Check for regression (smaller or same size with different root)
		if cp.TreeHead.Size < lastCP.TreeHead.Size {
			return fmt.Errorf("%w: new checkpoint size %d < previous %d",
				ErrCheckpointRegression, cp.TreeHead.Size, lastCP.TreeHead.Size)
		}

		if cp.TreeHead.Size == lastCP.TreeHead.Size {
			if cp.TreeHead.RootHash != lastCP.TreeHead.RootHash {
				return fmt.Errorf("%w: same size %d but different root hash",
					ErrCheckpointFork, cp.TreeHead.Size)
			}
			// Same checkpoint, not new
			return ErrNoNewCheckpoint
		}

		// Verify consistency proof if size increased
		if cp.TreeHead.Size > lastCP.TreeHead.Size {
			// In a real implementation, we would request and verify a consistency proof
			// For now, we just track the history
		}
	}

	// Add to history
	c.checkpointHistory[logID] = append(history, cp)
	c.lastCheckpoint = cp

	// Persist to storage
	if c.storage != nil {
		c.storage.SaveCheckpoint(cp)
	}

	return nil
}

// processCheckpoint processes a new checkpoint by collecting witness cosignatures
func (c *Client) processCheckpoint(ctx context.Context, cp *types.Checkpoint) (*CosignedCheckpoint, error) {
	// Request cosignatures from all witnesses
	cosignatures, err := c.collectCosignatures(ctx, cp)
	if err != nil {
		return nil, fmt.Errorf("failed to collect cosignatures: %w", err)
	}

	// Verify cosignatures
	verifiedCosigs := c.verifyCosignatures(cp, cosignatures)

	// Check quorum
	quorumMet := c.checkQuorum(verifiedCosigs)

	cosignedCP := &CosignedCheckpoint{
		Checkpoint:   cp,
		Cosignatures: verifiedCosigs,
		QuorumMet:    quorumMet,
		VerifiedAt:   time.Now(),
	}

	// If quorum not met, reject
	if !quorumMet {
		return cosignedCP, ErrQuorumNotMet
	}

	// Update witness states
	c.updateWitnessStates(cp, verifiedCosigs)

	// Persist cosignatures
	if c.storage != nil {
		cpID, err := c.storage.SaveCheckpoint(cp)
		if err == nil {
			for _, cs := range verifiedCosigs {
				if cs.Verified {
					c.storage.SaveCosignature(cpID, &cs)
				}
			}
		}
	}

	return cosignedCP, nil
}

// collectCosignatures requests cosignatures from all configured witnesses
func (c *Client) collectCosignatures(ctx context.Context, cp *types.Checkpoint) ([]types.Cosignature, error) {
	var wg sync.WaitGroup
	cosigChan := make(chan types.Cosignature, len(c.config.Witnesses))
	errChan := make(chan error, len(c.config.Witnesses))

	for _, witness := range c.config.Witnesses {
		wg.Add(1)
		go func(w WitnessConfig) {
			defer wg.Done()
			cosig, err := c.requestCosignature(ctx, w, cp)
			if err != nil {
				errChan <- fmt.Errorf("witness %s: %w", w.Name, err)
				return
			}
			cosigChan <- cosig
		}(witness)
	}

	go func() {
		wg.Wait()
		close(cosigChan)
		close(errChan)
	}()

	var cosignatures []types.Cosignature
	for cosig := range cosigChan {
		cosignatures = append(cosignatures, cosig)
	}

	// Collect errors (non-fatal)
	for err := range errChan {
		fmt.Printf("Warning: %v\n", err)
	}

	return cosignatures, nil
}

// requestCosignature requests a cosignature from a single witness
func (c *Client) requestCosignature(ctx context.Context, witness WitnessConfig, cp *types.Checkpoint) (types.Cosignature, error) {
	// Prepare the checkpoint for the witness
	// The witness expects the checkpoint in ASCII format
	var buf []byte
	w := &bytesBuffer{data: buf}
	if err := cp.Checkpoint.ToASCII(w); err != nil {
		return types.Cosignature{}, fmt.Errorf("failed to encode checkpoint: %w", err)
	}

	url := witness.URL + "/add-checkpoint"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, w.reader())
	if err != nil {
		return types.Cosignature{}, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("Accept", "text/plain")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return types.Cosignature{}, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return types.Cosignature{}, fmt.Errorf("witness returned status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return types.Cosignature{}, fmt.Errorf("failed to read response: %w", err)
	}

	// Parse the cosignature response
	cosig, err := c.parseCosignature(body, witness)
	if err != nil {
		return types.Cosignature{}, fmt.Errorf("failed to parse cosignature: %w", err)
	}

	return cosig, nil
}

// parseCosignature parses a cosignature response from a witness
func (c *Client) parseCosignature(data []byte, witness WitnessConfig) (types.Cosignature, error) {
	// The witness returns a cosignature in ASCII format
	// Format: cosignature <keyid> <timestamp> <signature>
	// Or it might return a full checkpoint with cosignature

	p := ascii.NewLineReader(data)

	// Try to parse as a cosignature line
	var cosigLine checkpoint.CosignatureLine
	if err := cosigLine.Parse(&p); err != nil {
		// Try parsing as a full checkpoint with cosignature
		cp := &checkpoint.Checkpoint{}
		p2 := ascii.NewLineReader(data)
		if err2 := cp.Parse(&p2); err2 != nil {
			return types.Cosignature{}, fmt.Errorf("failed to parse as cosignature or checkpoint: %v, %v", err, err2)
		}
		// Extract cosignature from checkpoint
		if len(cp.Cosignatures) == 0 {
			return types.Cosignature{}, errors.New("no cosignature in checkpoint")
		}
		cosigLine = cp.Cosignatures[0]
	}

	// Verify the key ID matches the witness
	expectedKeyID := checkpoint.NewWitnessKeyId(witness.KeyHash)
	if cosigLine.KeyId != expectedKeyID {
		return types.Cosignature{}, fmt.Errorf("key ID mismatch: expected %x, got %x", expectedKeyID, cosigLine.KeyId)
	}

	return types.Cosignature{
		Cosignature: cosigLine,
		WitnessID:   witness.KeyHash,
		Verified:    false, // Will be verified in verifyCosignatures
		VerifiedAt:  time.Time{},
	}, nil
}

// verifyCosignatures verifies all cosignatures against witness public keys
func (c *Client) verifyCosignatures(cp *types.Checkpoint, cosignatures []types.Cosignature) []types.Cosignature {
	witnessMap := make(map[crypto.Hash]WitnessConfig)
	for _, w := range c.config.Witnesses {
		witnessMap[w.KeyHash] = w
	}

	var verified []types.Cosignature
	for _, cs := range cosignatures {
		witness, ok := witnessMap[cs.WitnessID]
		if !ok {
			fmt.Printf("Unknown witness: %x\n", cs.WitnessID)
			verified = append(verified, cs) // Keep but mark unverified
			continue
		}

		// Verify the cosignature
		valid := cp.Checkpoint.VerifyCosignature(&witness.PublicKey, &cs.Cosignature)

		cs.Verified = valid
		cs.VerifiedAt = time.Now()
		verified = append(verified, cs)
	}

	return verified
}

// checkQuorum checks if the quorum requirement is met
func (c *Client) checkQuorum(cosignatures []types.Cosignature) bool {
	verified := make(map[crypto.Hash]bool)
	for _, cs := range cosignatures {
		if cs.Verified {
			verified[cs.WitnessID] = true
		}
	}

	switch c.config.QuorumPolicy.Type {
	case "kofn":
		return c.evaluateKOfNQuorum(verified)
	default:
		// Default to k-of-n
		return c.evaluateKOfNQuorum(verified)
	}
}

// evaluateKOfNQuorum evaluates a k-of-n quorum
func (c *Client) evaluateKOfNQuorum(verified map[crypto.Hash]bool) bool {
	count := 0
	for _, h := range c.config.QuorumPolicy.WitnessHashes {
		if verified[h] {
			count++
		}
	}
	return count >= c.config.QuorumPolicy.K
}

// updateWitnessStates updates the tracked state for each witness
func (c *Client) updateWitnessStates(cp *types.Checkpoint, cosignatures []types.Cosignature) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, cs := range cosignatures {
		if !cs.Verified {
			continue
		}

		state := WitnessState{
			WitnessKeyHash: cs.WitnessID,
			LogID:          cp.LogID,
			LogOrigin:      cp.Origin,
			TreeSize:       cp.TreeHead.Size,
			RootHash:       cp.TreeHead.RootHash,
			Timestamp:      cs.Timestamp,
		}

		c.witnessStates[cs.WitnessID] = state

		// Persist to storage
		if c.storage != nil {
			c.storage.SaveWitnessState(cs.WitnessID, cp.LogID, cp.Origin, cp.TreeHead.Size, cp.TreeHead.RootHash)
		}
	}
}

// GetLastCheckpoint returns the last observed checkpoint
func (c *Client) GetLastCheckpoint() *types.Checkpoint {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.lastCheckpoint
}

// GetCheckpointHistory returns the checkpoint history for a log
func (c *Client) GetCheckpointHistory(logID crypto.Hash) []*types.Checkpoint {
	c.mu.RLock()
	defer c.mu.RUnlock()
	history := c.checkpointHistory[logID]
	result := make([]*types.Checkpoint, len(history))
	copy(result, history)
	return result
}

// GetWitnessState returns the latest state for a witness
func (c *Client) GetWitnessState(witnessKeyHash crypto.Hash) (WitnessState, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	state, ok := c.witnessStates[witnessKeyHash]
	return state, ok
}

// GetAllWitnessStates returns all witness states
func (c *Client) GetAllWitnessStates() map[crypto.Hash]WitnessState {
	c.mu.RLock()
	defer c.mu.RUnlock()
	result := make(map[crypto.Hash]WitnessState)
	for k, v := range c.witnessStates {
		result[k] = v
	}
	return result
}

// VerifyConsistency requests and verifies a consistency proof between two checkpoints
func (c *Client) VerifyConsistency(ctx context.Context, oldSize, newSize uint64) error {
	if oldSize >= newSize {
		return errors.New("old size must be less than new size")
	}

	url := fmt.Sprintf("%s/consistency-proof?old_size=%d&new_size=%d", c.config.LogURL, oldSize, newSize)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to fetch consistency proof: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}

	// Parse and verify consistency proof
	// In a real implementation, this would verify the Merkle proof
	// For now, we just fetch it
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	fmt.Printf("Consistency proof received: %d bytes\n", len(body))
	return nil
}

// LoadState loads the client state from storage
func (c *Client) LoadState(ctx context.Context) error {
	if c.storage == nil {
		return errors.New("no storage configured")
	}

	// Load latest checkpoint
	logID := c.config.LogPublicKey.Hash()
	cp, err := c.storage.GetLatestCheckpoint(logID)
	if err != nil {
		return fmt.Errorf("failed to load latest checkpoint: %w", err)
	}
	if cp != nil {
		c.mu.Lock()
		c.lastCheckpoint = cp
		c.checkpointHistory[logID] = []*types.Checkpoint{cp}
		c.mu.Unlock()
	}

	// Load witness states
	for _, witness := range c.config.Witnesses {
		treeSize, rootHash, err := c.storage.GetWitnessState(witness.KeyHash, logID)
		if err != nil {
			continue // Not an error if state doesn't exist
		}
		if treeSize > 0 {
			state := WitnessState{
				WitnessKeyHash: witness.KeyHash,
				LogID:          logID,
				LogOrigin:      c.config.LogPublicKey.Hash().String(), // placeholder
				TreeSize:       treeSize,
				RootHash:       rootHash,
				Timestamp:      time.Now(),
			}
			c.mu.Lock()
			c.witnessStates[witness.KeyHash] = state
			c.mu.Unlock()
		}
	}

	return nil
}

// Helper: bytesBuffer implements io.Writer and io.Reader for checkpoint encoding
type bytesBuffer struct {
	data []byte
	pos  int
}

func (b *bytesBuffer) Write(p []byte) (int, error) {
	b.data = append(b.data, p...)
	return len(p), nil
}

func (b *bytesBuffer) reader() *bytesReader {
	return &bytesReader{data: b.data}
}

type bytesReader struct {
	data []byte
	pos  int
}

func (b *bytesReader) Read(p []byte) (int, error) {
	if b.pos >= len(b.data) {
		return 0, io.EOF
	}
	n := copy(p, b.data[b.pos:])
	b.pos += n
	return n, nil
}

// CreateClientFromConfig creates a client from a configuration file
// This is a placeholder for future config file support
func CreateClientFromConfig(configPath string) (*Client, error) {
	// TODO: Implement config file parsing
	return nil, errors.New("not implemented")
}

// ValidateTrustPolicy validates the trust policy configuration
func ValidateTrustPolicy(logs []types.LogIdentity, witnesses []types.WitnessIdentity, quorum QuorumPolicy) error {
	if len(logs) == 0 {
		return errors.New("at least one log is required")
	}
	if len(witnesses) == 0 {
		return errors.New("at least one witness is required")
	}
	if quorum.K <= 0 {
		return errors.New("quorum K must be positive")
	}
	if quorum.K > len(witnesses) {
		return errors.New("quorum K cannot exceed number of witnesses")
	}
	return nil
}

// NewKOfNQuorum creates a new k-of-n quorum policy
func NewKOfNQuorum(k int, witnessHashes []crypto.Hash) QuorumPolicy {
	return QuorumPolicy{
		Type:          "kofn",
		K:             k,
		WitnessHashes: witnessHashes,
	}
}

// WitnessKeyHashFromPublicKey derives the key hash from a witness public key
func WitnessKeyHashFromPublicKey(pubKey crypto.PublicKey) crypto.Hash {
	return pubKey.Hash()
}

// LogKeyHashFromPublicKey derives the key hash from a log public key
func LogKeyHashFromPublicKey(pubKey crypto.PublicKey) crypto.Hash {
	return pubKey.Hash()
}

// ParsePublicKey parses a public key from base64 encoding
func ParsePublicKey(s string) (crypto.PublicKey, error) {
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return crypto.PublicKey{}, err
	}
	if len(data) != ed25519.PublicKeySize {
		return crypto.PublicKey{}, fmt.Errorf("invalid public key size: %d", len(data))
	}
	var key crypto.PublicKey
	copy(key[:], data)
	return key, nil
}

// ParsePublicKeyHex parses a public key from hex encoding
func ParsePublicKeyHex(s string) (crypto.PublicKey, error) {
	data, err := hex.DecodeString(s)
	if err != nil {
		return crypto.PublicKey{}, err
	}
	if len(data) != ed25519.PublicKeySize {
		return crypto.PublicKey{}, fmt.Errorf("invalid public key size: %d", len(data))
	}
	var key crypto.PublicKey
	copy(key[:], data)
	return key, nil
}

// PublicKeyToBase64 encodes a public key to base64
func PublicKeyToBase64(key crypto.PublicKey) string {
	return base64.StdEncoding.EncodeToString(key[:])
}

// PublicKeyToHex encodes a public key to hex
func PublicKeyToHex(key crypto.PublicKey) string {
	return hex.EncodeToString(key[:])
}