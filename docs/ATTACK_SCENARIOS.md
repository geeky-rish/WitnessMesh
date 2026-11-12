# WitnessMesh Attack Scenarios & Reproduction Runbook

**Document Version:** 1.0.0  
**Domain:** Attack Simulation, Anomaly Detection & Incident Response  
**Engine Implementation:** `internal/attack/attack.go`  

---

## 1. Overview & Simulation Architecture

WitnessMesh features a built-in Attack Simulation Engine (`internal/attack`) capable of orchestrating reproducible, multi-node cryptographic attacks against the live transparency mesh. Each scenario validates specific security properties: append-only integrity, witness monotonicity, Byzantine quorum safety, and automated quarantine.

Scenarios can be executed in two ways:
1. **Command Line Interface (CLI):** Direct execution via the unified binary:
   ```bash
   ./witnessmesh -mode attack -attack <scenario-name>
   ```
2. **Interactive Web Dashboard:** From the **Attack Laboratory** tab (`/attack-lab`), which provides real-time event logs, visual state transitions, and instant evidence generation.

---

## 2. Attack Scenarios Catalog

### Scenario 1: `honest-baseline`
- **Category:** Baseline / Control
- **Description:** Normal operational state. The transparency log appends records monotonically, produces valid RFC 6962 consistency proofs, and distributes checkpoints to honest witnesses.
- **Attack Vector:** None (Control execution).
- **Observed Behavior:**
  - Log tree size increments from 1 to 5.
  - All 3 witnesses verify consistency proofs and return valid Ed25519 cosignatures.
  - Clients observe full 3-of-3 quorum ($k=2$ requirement satisfied).
  - Monitor logs zero anomalies.
- **Execution Command:**
  ```bash
  ./witnessmesh -mode attack -attack honest-baseline
  ```

---

### Scenario 2: `split-view-rollback`
- **Category:** State Rollback & Split-View Fork
- **Description:** A malicious log attempts to present two divergent histories to different clients. To force a witness into accepting an incompatible branch, the attacker snapshots and rolls back `witness-0`'s SQLite database to a previous tree state.
- **Attack Mechanics:**
  1. Log advances to tree size 5 ($R_1$) and all witnesses cosign.
  2. Attacker snapshots `witness-0`'s database at size 5.
  3. Log advances along Branch A to tree size 10 ($R_A$). `witness-0` cosigns size 10.
  4. Attacker terminates `witness-0` and restores the database snapshot back to size 5.
  5. Malicious log presents Branch B (size 10, root $R_B$, where $R_B \ne R_A$) to `witness-0`.
  6. Because its local database was rolled back to size 5, `witness-0` accepts Branch B and issues a cosignature for $R_B$.
  7. The Monitor detects that `witness-0` signed two conflicting roots for tree size 10.
- **Detection & Remediation:**
  - Anomaly detected: `WitnessRollback` & `LogEquivocation`.
  - Evidence bundle saved to `data/evidence.json`.
  - Offline verifier proves the violation mathematically.
  - Policy engine excludes `witness-0` from active quorum.
- **Execution Command:**
  ```bash
  ./witnessmesh -mode attack -attack split-view-rollback
  ```

---

### Scenario 3: `witness-equivocation`
- **Category:** Compromised Witness Malfeasance
- **Description:** A compromised witness intentionally cosigns two conflicting checkpoints for the exact same tree size ($S=10$) without requiring a database rollback.
- **Attack Mechanics:**
  1. The log produces two validly signed checkpoints for tree size 10: Checkpoint $A$ (Root $R_A$) and Checkpoint $B$ (Root $R_B$).
  2. Malicious/compromised `witness-1` issues valid Ed25519 cosignatures on BOTH checkpoints.
  3. Monitor collects cosignatures from `witness-1` for $R_A$ and $R_B$.
- **Detection & Remediation:**
  - Monitor compiles `EvidenceBundle` containing both signed checkpoint lines.
  - The Policy Engine marks `witness-1` as Byzantine and permanently revokes its key.
  - A cryptographic revocation event is committed to the SHA-256 tamper-evident audit log.
- **Execution Command:**
  ```bash
  ./witnessmesh -mode attack -attack witness-equivocation
  ```

---

### Scenario 4: `collusion`
- **Category:** Malicious Log & Witness Sub-Quorum Collusion
- **Description:** A malicious log colludes with a minority subset of witnesses ($f=1$ in a 3-witness network where $k=2$) to promote an unverified, fraudulent checkpoint root.
- **Attack Mechanics:**
  1. The malicious log fabricates a fake checkpoint root $R_{\text{fake}}$.
  2. Colluding `witness-0` signs $R_{\text{fake}}$.
  3. Honest witnesses (`witness-1` and `witness-2`) reject $R_{\text{fake}}$ because no valid consistency proof exists.
  4. The log presents $R_{\text{fake}}$ with 1 cosignature to Client 0.
- **Detection & Remediation:**
  - Client checks quorum policy ($k=2$).
  - Only 1 valid cosignature is present ($1 < 2$).
  - Client rejects the checkpoint and logs a `QuorumNotMet` incident.
  - Safety is preserved: $2k - n > f \implies 4 - 3 = 1 > 0$.
- **Execution Command:**
  ```bash
  ./witnessmesh -mode attack -attack collusion
  ```

---

### Scenario 5: `network-partition`
- **Category:** Distributed Network Partition / Fault Tolerance
- **Description:** Simulates an asynchronous network partition that isolates $n - k + 1$ witnesses from the client and monitor.
- **Attack Mechanics:**
  1. Communication between Client 1 and `witness-1`, `witness-2` is severed.
  2. The log publishes new tree heads.
  3. Client 1 can only reach `witness-0` (1 cosignature).
- **Detection & Remediation:**
  - Client 1 detects that quorum threshold $k=2$ cannot be reached.
  - Client 1 halts state progression (liveness paused) rather than accepting an unconfirmed root (safety prioritized).
  - Once the partition heals, Client 1 receives pending cosignatures and resumes normal verification.
- **Execution Command:**
  ```bash
  ./witnessmesh -mode attack -attack network-partition
  ```

---

### Scenario 6: `stale-checkpoint`
- **Category:** Replay / Freshness Attack
- **Description:** A malicious or degraded log attempts to suppress new append operations by serving an outdated checkpoint whose timestamp exceeds the client's freshness threshold.
- **Attack Mechanics:**
  1. Log serves a validly signed checkpoint with timestamp $T_{\text{old}}$ ($T_{\text{now}} - T_{\text{old}} > \text{MaxAge}$).
  2. Client validates signatures and tree size, then inspects the checkpoint freshness timestamp.
- **Detection & Remediation:**
  - Client rejects the checkpoint as stale.
  - Incident `StaleCheckpoint` logged in SQLite.
- **Execution Command:**
  ```bash
  ./witnessmesh -mode attack -attack stale-checkpoint
  ```

---

## 3. End-to-End Verification of Attack Results

After executing an attack scenario, run the standalone offline verifier to inspect the generated evidence bundle:

```bash
./witnessmesh -mode verify -evidence data/evidence.json
```

**Expected Verifier Output:**
```
=== VERIFICATION RESULT ===
File: data/evidence.json
Valid: true
Case: WitnessEquivocation
Description: Witness equivocation: single witness signing conflicting checkpoints

STATUS: VALID - Cryptographic evidence establishes the stated inconsistency
```

---

## 4. Support & Inquiries

For technical questions or to report attack vectors, please contact:
- **Maintainer:** Rishi Kulkarni
- **GitHub:** [@geeky-rish](https://github.com/geeky-rish)
- **Email:** `chingi11@proton.me`
