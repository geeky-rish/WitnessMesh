# WitnessMesh Architecture Specification

**System Version:** 1.0.0  
**Compliance:** RFC 6962 (Certificate Transparency), RFC 9162 (Binary Transparency), C2SP `tlog-witness`  
**Target Environment:** Cryptography & Network Security (CNS) Distributed Systems  

---

## 1. Executive Overview

WitnessMesh is a distributed cryptographic trust-monitoring and attack-detection architecture designed for append-only transparency logs. Transparency logs provide verifiable auditability by organizing data into Merkle trees and signing tree heads (Signed Tree Heads / Checkpoints). However, a malicious or compromised log operator can execute **split-view attacks**—serving distinct, conflicting tree heads to different clients to conceal unauthorized records.

WitnessMesh prevents and detects such attacks by deploying an independent, gossip-connected mesh of **C2SP tlog-witnesses**. Witnesses guarantee that a log's state progresses monotonically: they verify RFC 6962 consistency proofs before issuing cryptographic cosignatures. Clients only accept checkpoints that achieve a Byzantine-fault-tolerant quorum ($k$-of-$n$). Any divergence triggers deterministic evidence bundle generation, automatic quarantine of malicious nodes, and mathematically binding offline verification.

```
                    ┌──────────────────────────────────────────────┐
                    │            Transparency Log Service          │
                    │        (RFC 6962 Append-Only Merkle Tree)    │
                    └───────┬───────────────────────────────┬──────┘
                            │ /tree-head                    │ Checkpoint + Proofs
                            ▼                               ▼
                 ┌────────────────────┐          ┌────────────────────┐
                 │  Witness Node 0    │          │  Witness Node 1    │
                 │ (C2SP Monotone DB) │          │ (C2SP Monotone DB) │
                 └─────────┬──────────┘          └─────────┬──────────┘
                           │                               │
                           │   Ed25519 Cosignatures        │
                           └───────────────┬───────────────┘
                                           ▼
                 ┌─────────────────────────────────────────────────┐
                 │        Byzantine Quorum & Gossip Monitor        │
                 │   - Quorum Safety Validation: 2k - n > f        │
                 │   - Anomaly & Equivocation Detector             │
                 │   - Tamper-Evident SHA-256 Policy Audit Log     │
                 └───────┬─────────────────────────────────┬───────┘
                         │                                 │
                         ▼                                 ▼
         ┌───────────────────────────────┐ ┌───────────────────────────────┐
         │     Client Quorum Verifier    │ │   Standalone Offline Verifier │
         │   (Rejects Non-Quorum Roots)  │ │   (Zero-Network Proof Engine) │
         └───────────────────────────────┘ └───────────────────────────────┘
```

---

## 2. Core Subsystems

### 2.1 Transparency Log Service (`internal/log`)

The Transparency Log maintains the append-only ledger:
- **Merkle Tree Construction:** Built following RFC 6962 and RFC 9162 standards.
  - Leaf hash: $H(\text{0x00} \parallel \text{leaf\_data})$
  - Interior node hash: $H(\text{0x01} \parallel \text{left\_child} \parallel \text{right\_child})$
  - Hash algorithm: SHA-256 (`crypto.HashBytes`)
- **Tree Signing:** Checkpoints are signed using Ed25519 (`sigsum.org/sigsum-go/pkg/crypto`).
- **Proof Generation:**
  - **Inclusion Proofs:** Demonstrates that a specific leaf exists at index $i$ in a tree of size $N$.
  - **Consistency Proofs:** Demonstrates that an older tree of size $M$ forms an exact prefix of a newer tree of size $N$ ($M \le N$).
- **Dual-View Simulation Mode:** For evaluation and attack demonstration, the log can operate in malicious mode, maintaining two diverging Merkle forks with different cryptographic root hashes.

### 2.2 C2SP Witness Nodes (`internal/witness`)

Each witness is an autonomous daemon implementing the C2SP `tlog-witness` protocol:
- **Monotone State Invariant:** A witness records the latest verified tree size $S_{\text{latest}}$ and root hash $R_{\text{latest}}$ in persistent SQLite storage.
- **Verification Pipeline:**
  1. Parse incoming checkpoint formatted under the C2SP checkpoint specification.
  2. Verify the log's Ed25519 signature over the signed tree head.
  3. Validate monotonicity:
     - If $S_{\text{new}} < S_{\text{latest}}$: Reject as backwards regression.
     - If $S_{\text{new}} = S_{\text{latest}}$ and $R_{\text{new}} \ne R_{\text{latest}}$: Reject as equivocation.
     - If $S_{\text{new}} > S_{\text{latest}}$: Verify the RFC 6962 consistency proof between $S_{\text{latest}}$ and $S_{\text{new}}$.
  4. If and only if the proof is valid, store $(S_{\text{new}}, R_{\text{new}})$ atomically and return an Ed25519 cosignature line.

### 2.3 Client Simulator & Quorum Verifier (`internal/client`)

Clients represent end-users querying log heads (e.g., certificate transparency monitors, package registry clients):
- **Monotonic Progression Check:** Clients cache their highest seen tree size and verify consistency proofs on updates.
- **Quorum Enforcement:** A checkpoint is rejected unless signed by at least $k$ distinct trusted witnesses.
- **Fork Rejection:** If an unverified checkpoint is presented by a malicious log, the client queries its witness pool. If witnesses refuse to cosign or report an inconsistent root, the client aborts.

### 2.4 Monitoring & Anomaly Detection Engine (`internal/monitor`)

The monitoring service acts as a gossip observer:
- Periodically polls the transparency log and all witness nodes.
- Correlates observed signed tree heads across time and space.
- Detects anomalies:
  - **Same-Size Log Fork:** Two checkpoints from the same log with identical size but distinct Merkle roots.
  - **Different-Size Log Fork:** Two checkpoints where the log cannot supply a valid consistency proof.
  - **Witness Equivocation:** A witness issuing cosignatures for conflicting root hashes.
  - **Witness Rollback:** A witness accepting a lower tree size than previously signed.
- Produces canonical **Evidence Bundles** upon detecting any violation.

### 2.5 Trust Policy Engine (`internal/policy`)

The policy engine manages network membership and mathematical quorum bounds:
- **Byzantine Parameter Enforcement:**
  - Safety bound: $2k - n > f$
  - Liveness bound: $k \le n - f$
  - Where $n$ is total witnesses, $k$ is required quorum size, and $f$ is the maximum number of tolerated Byzantine (compromised) witnesses.
- **Dynamic Witness Exclusion:** When valid cryptographic proof of witness misbehavior is presented, the witness is instantly revoked.
- **Tamper-Evident Audit Trail:** Every policy alteration is stored in an append-only SQLite table with SHA-256 hash chaining:
  $$\text{Hash}_i = \text{SHA-256}(\text{Hash}_{i-1} \parallel \text{Timestamp} \parallel \text{Action} \parallel \text{Payload})$$

### 2.6 Offline Cryptographic Evidence Verifier (`internal/verifier`)

A standalone, zero-network verification utility:
- Parses serialized JSON or deterministic binary evidence bundles.
- Cryptographically validates:
  - Log signatures against configured trusted public keys.
  - Witness cosignatures against configured trusted witness public keys.
  - RFC 6962 consistency proofs between conflicting tree sizes.
  - Disjointness of Merkle roots in equivocation scenarios.
- Produces a deterministic boolean verdict (`VALID` / `INVALID`) with human-readable diagnostic errors.

### 2.7 Interactive Web Dashboard (`web/`)

A single-page application built with React 18, TypeScript, Tailwind CSS, and Vite:
- **Overview:** Real-time system health, active node counts, and quorum status.
- **Network Topology:** Interactive ReactFlow visualization displaying live node states and message flows.
- **Attack Laboratory:** One-click launcher for all 6 reproducible attack simulations.
- **Witness Monitoring:** Detailed view of each witness's latest tree size, root hash, and latency.
- **Checkpoints:** Merkle tree inspector and checkpoint signature tracker.
- **Evidence Verification:** Drag-and-drop evidence bundle validator.
- **Incident History:** Real-time log of security events and classifications.
- **Trust Policies:** Interactive $n, k, f$ quorum calculator and audit log viewer.
- **Settings:** Endpoint configuration, polling timers, and maintainer metadata.

---

## 3. Distributed Data Flows

### 3.1 Checkpoint Publication and Cosigning Sequence

```
Log                    Witness-0             Witness-1             Monitor
 │                         │                     │                    │
 │ 1. Create Tree Head     │                     │                    │
 ├─────────────────────────┼─────────────────────┼───────────────────►│ (Gossip Poll)
 │                         │                     │                    │
 │ 2. POST /add-checkpoint │                     │                    │
 │    (old_size, STH, pf)  │                     │                    │
 ├────────────────────────►│                     │                    │
 │                         │ 3. Verify STH & Pf  │                    │
 │                         │ 4. Persist (atomic) │                    │
 │    200 OK (Cosignature) │                     │                    │
 │◄────────────────────────┤                     │                    │
 │                         │                     │                    │
 │ 5. POST /add-checkpoint │                     │                    │
 ├──────────────────────────────────────────────►│                    │
 │                         │                     │ 6. Verify STH & Pf │
 │                         │                     │ 7. Persist (atomic)│
 │    200 OK (Cosignature) │                     │                    │
 │◄──────────────────────────────────────────────┤                    │
 │                         │                     │                    │
 │ 8. Checkpoint with      │                     │                    │
 │    Quorum (2-of-2)      │                     │                    │
 └─────────────────────────┴─────────────────────┴───────────────────►│
```

### 3.2 Inconsistency Detection & Quarantine Sequence

```
Malicious Log              Witness-0 (Corrupt)      Monitor           Policy Engine
      │                            │                   │                    │
      │ 1. Fork Tree (Root A / B)  │                   │                    │
      ├───────────────────────────►│                   │                    │
      │    (Accepts Root A)        │                   │                    │
      │                            │ 2. Cosign(A)      │                    │
      │                            ├──────────────────►│                    │
      │ 3. Send Root B             │                   │                    │
      ├───────────────────────────►│                   │                    │
      │    (Accepts Root B)        │                   │                    │
      │                            │ 4. Cosign(B)      │                    │
      │                            ├──────────────────►│                    │
      │                            │                   │ 5. Detect Conflict │
      │                            │                   │    (Root A != B)   │
      │                            │                   │ 6. Build Evidence  │
      │                            │                   │    Bundle          │
      │                            │                   │ 7. Submit Evidence │
      │                            │                   ├───────────────────►│
      │                            │                   │                    │ 8. Offline Verify
      │                            │                   │                    │ 9. Revoke Witness-0
      │                            │                   │                    │ 10. Append Audit Log
```

---

## 4. Storage Architecture

WitnessMesh utilizes embedded SQLite with Write-Ahead Logging (`PRAGMA journal_mode=WAL;`) and foreign keys enabled:

### 4.1 Schema Tables

1. **`checkpoints`**: Stores all signed tree heads received from logs and witnesses.
   - Primary key: `(origin, tree_size, root_hash)`
   - Columns: `signature`, `key_hash`, `timestamp`, `raw_checkpoint`
2. **`cosignatures`**: Stores cryptographic cosignatures associated with checkpoints.
   - Primary key: `(witness_id, origin, tree_size, root_hash)`
   - Columns: `signature`, `timestamp`, `raw_cosignature`
3. **`incidents`**: Logs detected security anomalies.
   - Columns: `id`, `incident_type`, `severity`, `log_id`, `description`, `evidence_id`, `status`, `timestamp`
4. **`evidence_bundles`**: Canonical JSON and binary evidence bundles.
   - Primary key: `bundle_id`
   - Columns: `case_type`, `data_json`, `data_binary`, `created_at`
5. **`policy_audit_log`**: Tamper-evident sequential audit log for governance operations.
   - Columns: `index`, `prev_hash`, `entry_hash`, `action`, `witness_id`, `payload`, `timestamp`
6. **`witness_state`**: Monotonic state storage for independent witness nodes.
   - Primary key: `(witness_name, log_origin)`
   - Columns: `tree_size`, `root_hash`, `updated_at`

---

## 5. Deployment Models

WitnessMesh can be executed under multiple runtime topologies:

1. **Integrated Demo Mode (`-mode demo`):** Runs the Transparency Log, 3 Witnesses, 2 Client Simulators, Monitoring Daemon, Policy Engine, and Web Dashboard inside a single unified process for rapid testing.
2. **Distributed Microservice Mode:** Individual binaries spawned with flags:
   - `-mode log -listen :8081`
   - `-mode witness -name witness-0 -listen :8082 -log http://localhost:8081`
   - `-mode client -listen :8085 -log http://localhost:8081`
   - `-mode monitor`
3. **Docker Compose:** Multi-container orchestration defined in `docker-compose.yml`.
4. **Standalone Offline Verifier (`-mode verify`):** Runs independently of any network daemon, processing raw files from disk.

---

## 6. Support & Inquiries

For technical questions, architecture reviews, or vulnerability reports, please contact:
- **Maintainer:** Rishi Kulkarni
- **GitHub:** [@geeky-rish](https://github.com/geeky-rish)
- **Email:** `chingi11@proton.me`
