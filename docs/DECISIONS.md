# WitnessMesh Architectural Decision Records (ADRs)

**Document Version:** 1.0.0  
**Project:** WitnessMesh Distributed Cryptographic Trust Architecture  

---

## Index of Decisions

- [ADR-001: Cryptographic Primitives: Ed25519 & SHA-256](#adr-001-cryptographic-primitives-ed25519--sha-256)
- [ADR-002: Adoption of C2SP tlog-witness Protocol](#adr-002-adoption-of-c2sp-tlog-witness-protocol)
- [ADR-003: Strict Byzantine Quorum Invariant (2k - n > f)](#adr-003-strict-byzantine-quorum-invariant-2k---n--f)
- [ADR-004: Standalone Zero-Dependency Offline Verifier](#adr-004-standalone-zero-dependency-offline-verifier)
- [ADR-005: Embedded SQLite Storage with Write-Ahead Logging (WAL)](#adr-005-embedded-sqlite-storage-with-write-ahead-logging-wal)
- [ADR-006: Dual Serialization: Canonical JSON and Deterministic Binary](#adr-006-dual-serialization-canonical-json-and-deterministic-binary)
- [ADR-007: Single-Binary Distribution with Embedded React Dashboard](#adr-007-single-binary-distribution-with-embedded-react-dashboard)

---

## ADR-001: Cryptographic Primitives: Ed25519 & SHA-256

### Status
Accepted

### Context
Transparency logs require fast digital signatures and collision-resistant hash trees capable of handling millions of entries without cryptographic degradation. RSA signatures are prohibitively large (256–512 bytes) and slow to verify, while ECDSA signatures are susceptible to catastrophic private key recovery if nonce generation is biased.

### Decision
Adopt Ed25519 (RFC 8032) for all log checkpoints and witness cosignatures, and SHA-256 (FIPS 180-4) with RFC 6962 domain prefixes (`0x00` leaf, `0x01` interior node) for all Merkle tree hashing.

### Consequences
- **Positive:** Deterministic 64-byte signatures, high verification throughput, constant-time operations immune to timing side-channels.
- **Negative:** Non-interoperable with legacy RSA-only Certificate Transparency monitors without an adapter.

---

## ADR-002: Adoption of C2SP tlog-witness Protocol

### Status
Accepted

### Context
Cosigning protocols in earlier transparency systems suffered from fragmented specifications. The Community Cryptography Specification Project (C2SP) formalizes `tlog-witness`, a protocol defining how witnesses verify tree heads and return monotone cosignatures.

### Decision
Implement the C2SP `tlog-witness` protocol (`POST /add-checkpoint`) as the primary interface between the transparency log, witnesses, and clients.

### Consequences
- **Positive:** Standardized checkpoint headers, clean separation between consistency proof evaluation and cosignature issuance, interoperability with Sigsum and Go transparency ecosystems.
- **Negative:** Requires witnesses to maintain persistent state for every monitored log origin.

---

## ADR-003: Strict Byzantine Quorum Invariant ($2k - n > f$)

### Status
Accepted

### Context
In distributed systems with $n$ witnesses, clients must require $k$ cosignatures before trusting a tree head. If $k$ is configured carelessly, a malicious log can fork the tree by obtaining two disjoint quorums with the assistance of $f$ colluding Byzantine witnesses.

### Decision
Enforce strict inequality $2k - n > f$ for safety and $k \le n - f$ for liveness. The Policy Engine rejects any configuration that violates strict inequality.

### Consequences
- **Positive:** Mathematically proves that every pair of quorums intersects in at least one strictly honest witness, making undetected split-views impossible.
- **Negative:** Restricts parameter selection (e.g., $n=3, k=2$ cannot tolerate $f=1$ Byzantine witness; $n=4, k=3$ is required for $f=1$).

---

## ADR-004: Standalone Zero-Dependency Offline Verifier

### Status
Accepted

### Context
Third-party auditors, regulators, or offline forensic investigators need to verify evidence of log or witness misbehavior without running daemons, connecting to SQLite, or making network requests.

### Decision
Implement `-mode verify` as an independent CLI routine within `internal/verifier`. It consumes raw evidence files from disk and relies exclusively on standard cryptographic operations.

### Consequences
- **Positive:** Zero attack surface during verification, deterministic execution, easily auditable in air-gapped environments.
- **Negative:** The verifier must receive trusted log and witness public keys out-of-band or embedded within the evidence bundle.

---

## ADR-005: Embedded SQLite Storage with Write-Ahead Logging (WAL)

### Status
Accepted

### Context
Witnesses must guarantee that tree size never regresses, even across crashes, power failures, or concurrent requests. Relying on in-memory state or flat files risks data loss or race conditions.

### Decision
Use embedded SQLite with `PRAGMA journal_mode=WAL;` and `PRAGMA synchronous=NORMAL;`. All witness updates are committed inside immediate write transactions.

### Consequences
- **Positive:** ACID durability, zero external database setup, high concurrency between reads and writes, portable single-file database.
- **Negative:** Requires `CGO_ENABLED=1` for compiling `github.com/mattn/go-sqlite3`.

---

## ADR-006: Dual Serialization: Canonical JSON and Deterministic Binary

### Status
Accepted

### Context
Evidence bundles need to be shared across diverse channels: human audit reports, web browser dashboards, and low-bandwidth gossip protocols between witnesses.

### Decision
Support two canonical representations:
1. **Canonical JSON:** For human readability, REST APIs, and web UI display.
2. **Deterministic Binary (TLV):** For compact peer-to-peer transmission and deterministic cryptographic hashing.

### Consequences
- **Positive:** Maximum flexibility for both automated and human consumption.
- **Negative:** Requires maintaining dual serializer/deserializer implementations in `internal/evidence`.

---

## ADR-007: Single-Binary Distribution with Embedded React Dashboard

### Status
Accepted

### Context
Deploying separate frontend web servers (Nginx/Node) alongside Go microservices complicates semester evaluation and standalone testing.

### Decision
Pre-bundle the React 18 + Vite frontend into `web/dist` and serve it directly via Go's `http.FileServer` with client-side SPA routing fallbacks in `cmd/witnessmesh/main.go`.

### Consequences
- **Positive:** Users can download a single binary, run `./witnessmesh -mode demo`, and immediately open `http://localhost:8080` in their browser.
- **Negative:** Rebuilding UI components requires a Node.js toolchain during frontend development.

---

## Support & Inquiries

For technical questions or to discuss architectural decisions, please contact:
- **Maintainer:** Rishi Kulkarni
- **GitHub:** [@geeky-rish](https://github.com/geeky-rish)
- **Email:** `chingi11@proton.me`
