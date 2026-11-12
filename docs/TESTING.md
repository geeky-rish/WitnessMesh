# WitnessMesh Cryptographic Test Plan & Security Matrix

**Document Version:** 1.0.0  
**Test Coverage:** Positive functional validation, negative security vectors, and Byzantine quorum boundaries.  
**Test Runners:** `go test` (standard Go test harness)  

---

## 1. Test Strategy Overview

WitnessMesh employs a rigorous, defense-in-depth test suite designed to ensure absolute cryptographic soundness. In cryptographic trust systems, **negative security testing** (confirming that forged, malformed, or manipulated evidence is deterministically rejected) is just as critical as positive functional validation.

The test suite spans:
1. **Cryptographic Verifier Negative Test Suite (`internal/verifier/verifier_test.go`):** 26 tests covering all 12 mandatory negative security vectors.
2. **Policy Engine & BFT Quorum Test Suite (`internal/policy/policy_test.go`):** Mathematical boundary checks for safety ($2k - n > f$) and liveness ($k \le n - f$), witness exclusion, and tamper-evident audit chaining.
3. **End-to-End System Evaluation (`scripts/demo.sh`):** Two-act live integration test spanning log, witnesses, monitor, and web UI.

---

## 2. Mandatory Negative Security Test Matrix (12 Vectors)

All 12 negative test vectors are implemented in `internal/verifier/verifier_test.go` and verified on every continuous integration run:

| Vector ID | Test Function | Injected Fault | Expected Verdict & Error |
|:---:|---|---|---|
| **V-01** | `TestNegative_CorruptedLogSignature` | Inverted byte in Ed25519 log signature on checkpoint | `INVALID`: signature verification failure |
| **V-02** | `TestNegative_TamperedRootHash` | Single-bit flip in 32-byte SHA-256 root hash | `INVALID`: signature does not match canonical target |
| **V-03** | `TestNegative_InvalidConsistencyProof` | Corrupted intermediate hash in RFC 6962 consistency path | `INVALID`: consistency proof evaluation failed |
| **V-04** | `TestNegative_NonMonotoneTreeSize` | Checkpoint tree size regresses without valid proof | `INVALID`: non-monotone checkpoint regression |
| **V-05** | `TestNegative_DuplicateCosignatures` | Replay of identical witness cosignature line | `INVALID`: redundant cosignature / duplicate witness |
| **V-06** | `TestNegative_UntrustedWitness` | Valid Ed25519 signature from unconfigured witness key | `INVALID`: untrusted witness public key |
| **V-07** | `TestNegative_MalformedCheckpointText` | Truncated lines or missing origin header | `INVALID`: checkpoint syntax parsing error |
| **V-08** | `TestNegative_CorruptedWitnessSignature` | Bit flip in witness Ed25519 cosignature | `INVALID`: witness signature verification failure |
| **V-09** | `TestNegative_ForgedWitnessID` | Witness ID does not match SHA-256 of public key | `INVALID`: witness key hash identity mismatch |
| **V-10** | `TestNegative_EmptyBundle` | Zero-length or null evidence payload | `INVALID`: evidence bundle is empty or corrupted |
| **V-11** | `TestNegative_IdenticalRootsInFork` | Same-size fork claimed, but roots are identical | `INVALID`: identical root hashes; no equivocation |
| **V-12** | `TestNegative_TruncatedBinary` | Binary evidence bundle truncated before end of stream | `INVALID`: unexpected EOF during binary deserialization |

---

## 3. Byzantine Quorum Policy Tests (`internal/policy`)

The policy engine test suite validates Byzantine Fault Tolerant quorum math and governance:

### 3.1 Strict Inequality Safety Tests
- Tests verify that $2k - n > f$ is enforced strictly:
  - For $n=5, k=3, f=1$: $2(3) - 5 = 1 \ngtr 1$. The test asserts that the engine correctly flags this configuration as **unsafe** against Byzantine equivocation.
  - For $n=4, k=3, f=1$: $2(3) - 4 = 2 > 1$. The test asserts that safety is guaranteed.

### 3.2 Liveness Boundary Tests
- Tests verify that $k \le n - f$ ensures progress:
  - For $n=3, k=3, f=1$: $k = 3 > n - f = 2$. The test asserts that the engine detects a liveness vulnerability (a single crash halts the system).

### 3.3 Dynamic Quarantine & Audit Log Chaining
- When an equivocation evidence bundle is ingested:
  1. Witness is transitioned from `Active` to `Revoked`.
  2. The updated active quorum is recalculated.
  3. An audit log entry is persisted with a SHA-256 hash linking to the previous entry:
     $$\text{Hash}_i = \text{SHA-256}(\text{Hash}_{i-1} \parallel \text{Timestamp} \parallel \text{Action} \parallel \text{Payload})$$
  4. The test verifies that the hash chain is strictly linear and tamper-evident.

---

## 4. Running the Test Suite

### 4.1 Running All Unit Tests
```bash
export PATH="/home/unknown92/go/bin:$PATH"
go test -v ./internal/...
```

### 4.2 Running Verifier Security Tests Specifically
```bash
go test -v -run TestNegative ./internal/verifier
```

### 4.3 Running Policy Engine Tests
```bash
go test -v ./internal/policy
```

### 4.4 Running with Race Detector
```bash
go test -race ./internal/...
```

### 4.5 Running Frontend Verification
```bash
cd web && npm run build && cd ..
```

---

## 5. Support & Inquiries

For technical questions or to report test edge cases, please contact:
- **Maintainer:** Rishi Kulkarni
- **GitHub:** [@geeky-rish](https://github.com/geeky-rish)
- **Email:** `chingi11@proton.me`
