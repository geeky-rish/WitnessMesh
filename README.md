# WitnessMesh: Distributed Cryptographic Trust Monitoring & Attack Detection

[![Go Report Card](https://goreportcard.com/badge/github.com/geeky-rish/WitnessMesh)](https://github.com/geeky-rish/WitnessMesh)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Standards: RFC 6962 / RFC 9162](https://img.shields.io/badge/Standards-RFC%206962%20%7C%20RFC%209162-success.svg)](https://datatracker.ietf.org/doc/html/rfc6962)
[![Protocol: C2SP tlog-witness](https://img.shields.io/badge/Protocol-C2SP%20tlog--witness-orange.svg)](https://c2sp.org/tlog-witness)

**WitnessMesh** is an open, distributed cryptographic trust-monitoring and attack-detection architecture for append-only transparency logs. It implements real RFC 6962 / RFC 9162 Merkle tree consistency proofs, C2SP `tlog-witness` cosignature protocols, Byzantine fault-tolerant quorum enforcement ($2k - n > f$), and an independent offline cryptographic evidence verifier.

Built as an engineering project for **Cryptography & Network Security (CNS)**.

---

## Key Capabilities

- **Strict Cryptography:** Ed25519 digital signatures, SHA-256 Merkle tree hashing with domain separation prefixes (`0x00` leaf, `0x01` interior node), and RFC 6962 consistency proof evaluation via `sigsum.org/sigsum-go`.
- **C2SP `tlog-witness` Monotonicity:** Independent witness nodes maintain persistent SQLite storage, verify consistency proofs before cosigning, and reject backwards or forked checkpoints.
- **Byzantine Quorum Safety & Liveness:** Mathematically enforces safety ($2k - n > f$) and liveness ($k \le n - f$). Detects equivocating nodes and dynamically isolates them with cryptographic accountability.
- **Offline Cryptographic Verifier:** Zero-network, zero-dependency standalone CLI tool (`-mode verify`) that parses deterministic binary/JSON evidence bundles and independently validates signatures and Merkle proofs.
- **Attack Simulation Suite:** Built-in engine simulating split-view attacks, witness SQLite state rollbacks, compromised witness equivocation, and sub-quorum collusion.
- **Enterprise Web UI:** React 18 + Vite dashboard with interactive topology maps (ReactFlow), attack lab console, real-time log inspector, and evidence verification portal.

---

## System Architecture

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

## Quick Start

### 1. Prerequisites
- **Go**: 1.22+ (`go version`)
- **Node.js**: 18+ (for building web dashboard, pre-built bundle included in `web/dist`)
- **SQLite3**: Required for CGO compilation

### 2. Build the System
```bash
# Build Go binary
export PATH="/home/unknown92/go/bin:$PATH"
CGO_ENABLED=1 go build -o witnessmesh ./cmd/witnessmesh

# (Optional) Rebuild React frontend
cd web && npm run build && cd ..
```

---

## Running the System

### Option A: Complete Demo Mode (Recommended)
Starts the Transparency Log, 3 Witnesses, 2 Client Simulators, Monitoring Engine, Trust Policy Engine, and the Web Dashboard on port 8080:

```bash
./witnessmesh -mode demo -listen :8080
```
Open **`http://localhost:8080`** in your browser to access the dashboard.

---

### Option B: Running Attack Scenarios

Run reproducible attack simulations against the live mesh:

```bash
# 1. Witness Database Rollback & Split-View Attack
./witnessmesh -mode attack -attack split-view-rollback

# 2. Compromised Witness Equivocation (Dual-Signing)
./witnessmesh -mode attack -attack witness-equivocation

# 3. Sub-Quorum Collusion Attack
./witnessmesh -mode attack -attack collusion

# 4. Network Partition Test
./witnessmesh -mode attack -attack network-partition

# 5. Honest Baseline Run
./witnessmesh -mode attack -attack honest-baseline
```

Evidence bundles are generated automatically and saved to `data/evidence.json`.

---

### Option C: Standalone Offline Cryptographic Verification

Verify an evidence bundle independently without running any network services:

```bash
./witnessmesh -mode verify -evidence data/evidence.json
```

**Output:**
```
=== VERIFICATION RESULT ===
File: data/evidence.json
Valid: true
Case: WitnessEquivocation
Description: Witness equivocation: single witness signing conflicting checkpoints

STATUS: VALID - Cryptographic evidence establishes the stated inconsistency
```

---

### Option D: Containerized Mesh (Docker Compose)

Spawn the distributed microservice mesh locally:

```bash
docker-compose up -d --build
```

---

## REST API Reference

When running in demo or server mode, WitnessMesh exposes the following HTTP endpoints:

| Endpoint | Method | Description |
|---|:---:|---|
| `/api/health` | `GET` | System uptime, node count, and maintainer metadata |
| `/api/log` | `GET` | Current signed tree head, size, and root hash |
| `/api/witnesses` | `GET` | List of active witnesses, public keys, and health status |
| `/api/checkpoints` | `GET` | Recent signed checkpoints and verification history |
| `/api/incidents` | `GET` | Security incidents detected by the monitoring daemon |
| `/api/evidence` | `GET` | Available cryptographic evidence bundles |
| `/api/policy` | `GET` | Active quorum parameters $(n, k, f)$ and witness roster |
| `/api/scenarios` | `GET` | List of available attack simulations |
| `/api/attack` | `POST` | Trigger an attack simulation (`{"scenario": "split-view-rollback"}`) |
| `/tree-head` | `GET` | RFC 6962 raw text checkpoint |
| `/add-leaf` | `POST` | Append an entry to the transparency log |

---

## Running Automated Tests

Run the full cryptographic verification and policy test suite:

```bash
export PATH="/home/unknown92/go/bin:$PATH"
go test -v ./internal/...
```

**Verification Results:**
- `internal/verifier`: 26/26 tests passing (100%), including all 12 negative security test vectors (corrupted signatures, tampered root hashes, invalid consistency paths, non-monotone regressions, forged keys, truncated payloads).
- `internal/policy`: 100% passing tests for strict safety ($2k - n > f$), liveness ($k \le n - f$), witness exclusion, and SHA-256 audit chaining.

---

## Documentation Roadmap

For in-depth specifications, consult the comprehensive documentation in `docs/`:

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — Detailed subsystem architecture, sequence flows, and database schemas.
- [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) — Attacker models, Byzantine quorum mathematical proofs, and security guarantees.
- [docs/PROTOCOLS.md](docs/PROTOCOLS.md) — RFC 6962 Merkle tree proofs, C2SP `tlog-witness` protocol, and gossip mechanics.
- [docs/EVIDENCE_FORMAT.md](docs/EVIDENCE_FORMAT.md) — Canonical JSON & deterministic binary evidence bundle specification.
- [docs/ATTACK_SCENARIOS.md](docs/ATTACK_SCENARIOS.md) — Operational runbook for all 6 reproducible attack simulations.
- [docs/TESTING.md](docs/TESTING.md) — Test matrix detailing all 12 negative security test vectors and verification instructions.
- [docs/DECISIONS.md](docs/DECISIONS.md) — Architectural Decision Records (ADRs 001–007).

---

## Project Structure

```
├── cmd/witnessmesh/          # Unified application entry point (demo, log, witness, client, verifier)
├── internal/
│   ├── attack/               # Multi-scenario attack simulation engine
│   ├── client/               # Transparency log client simulator & quorum verifier
│   ├── evidence/             # Evidence bundle generator, JSON & binary serializers
│   ├── log/                  # Transparency log service & Merkle tree engine
│   ├── monitor/              # Gossip & anomaly detection engine
│   ├── policy/               # Quorum policy engine & tamper-evident audit log
│   ├── storage/              # SQLite persistent storage driver (WAL mode)
│   ├── types/                # Core domain types & checkpoint structures
│   ├── verifier/             # Offline cryptographic evidence verifier
│   └── witness/              # C2SP tlog-witness protocol implementation
├── web/                      # React 18 + TypeScript + Tailwind admin dashboard
├── docs/                     # End-to-end engineering specifications
├── configs/                  # Configuration files
├── Dockerfile                # Multi-stage container definition
├── docker-compose.yml        # Distributed multi-container mesh
└── scripts/demo.sh           # Automated Two-Act evaluation script
```

---

## Support & Inquiries

For technical questions, cryptographic audits, or vulnerability disclosures, please contact:
- **Maintainer:** Rishi Kulkarni
- **GitHub:** [@geeky-rish](https://github.com/geeky-rish)
- **Email:** `chingi11@proton.me`

---

## License

This project is licensed under the MIT License. Built for Cryptography & Network Security (CNS).
