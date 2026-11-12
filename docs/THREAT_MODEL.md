# WitnessMesh Threat Model & Byzantine Security Analysis

**Document Version:** 1.0.0  
**Domain:** Distributed Cryptographic Trust & Transparency Logging  
**Mathematical Basis:** Byzantine Fault Tolerance (BFT) Quorum Systems  

---

## 1. System Goals & Security Objectives

The primary objective of WitnessMesh is to detect and cryptographically prove malicious behavior in append-only transparency systems. In particular:

1. **Non-Equivocation:** A transparency log operator MUST NOT be able to present two different tree heads (views) to different clients without detection.
2. **Monotonicity:** A transparency log MUST strictly grow. No entries may be deleted, replaced, or reordered.
3. **Accountability:** Any party (log operator or witness) that violates the protocol produces a mathematically undeniable, non-repudiable signature over its malfeasance.
4. **Resilience (BFT):** The system maintains safety (no false agreements on conflicting roots) and liveness (continual progress) in the presence of up to $f$ Byzantine (arbitrarily malicious or compromised) witnesses.
5. **Independent Verifiability:** Any third party, equipped solely with public keys and zero network connectivity, can unambiguously verify evidence bundles.

---

## 2. Adversary Classes & Capabilities

We analyze the system against four distinct adversary classes:

### 2.1 Adversary A: Malicious Transparency Log Operator
- **Capabilities:**
  - Possesses the log's Ed25519 private key.
  - Can forge new checkpoints, create forks, omit entries, or attempt backwards tree regressions.
  - Can target specific clients with customized split-views (targeted deception).
- **Constraints:**
  - Cannot forge witness Ed25519 signatures.
  - Cannot break SHA-256 collision resistance or invert preimage computations.

### 2.2 Adversary B: Compromised Witness Nodes
- **Capabilities:**
  - Possesses the Ed25519 private keys of up to $f$ witnesses.
  - Can cosign conflicting tree heads for the same tree size (equivocation).
  - Can attempt state rollbacks (e.g., restoring previous SQLite snapshots).
  - Can collude with a malicious log operator to help it reach quorum.
- **Constraints:**
  - Cannot compromise more than $f$ witness keys simultaneously without violating the quorum security threshold.

### 2.3 Adversary C: Network Adversary (Man-in-the-Middle)
- **Capabilities:**
  - Can delay, drop, duplicate, or reorder network packets.
  - Can temporarily partition witnesses or clients from the transparency log.
- **Constraints:**
  - Cannot forge cryptographic signatures or alter encrypted/authenticated payload contents.

### 2.4 Adversary D: Malicious Clients
- **Capabilities:**
  - Can submit invalid or forged evidence bundles to monitoring services.
  - Can attempt Denial of Service (DoS) by submitting high volumes of fake incident reports.
- **Constraints:**
  - Evaluated against the deterministic offline verifier, which instantly rejects syntactically or cryptographically invalid bundles.

---

## 3. Byzantine Quorum Formulation

WitnessMesh employs a parameterized quorum configuration defined by the tuple $(n, k, f)$:
- $n \in \mathbb{N}$: Total number of registered witnesses in the active mesh.
- $k \in \mathbb{N}$: Number of witness cosignatures required for a client to accept a checkpoint ($1 \le k \le n$).
- $f \in \mathbb{N}_0$: Maximum number of Byzantine (faulty or malicious) witnesses the network is designed to tolerate.

### 3.1 Safety Theorem: $2k - n > f$

> **Theorem 1 (Safety).** If $2k - n > f$, no two conflicting checkpoints (checkpoints representing disjoint or incompatible tree heads) can both obtain valid witness quorums.

#### Proof:
1. Let $Q_1$ and $Q_2$ be two valid witness quorums that have cosigned checkpoints $C_1$ and $C_2$, respectively.
2. By definition, $|Q_1| \ge k$ and $|Q_2| \ge k$, and both are subsets of the total witness pool $W$ with $|W| = n$.
3. By the inclusion-exclusion principle, the size of their intersection satisfies:
   $$|Q_1 \cap Q_2| = |Q_1| + |Q_2| - |Q_1 \cup Q_2| \ge k + k - n = 2k - n$$
4. Suppose for contradiction that $C_1$ and $C_2$ are conflicting, yet both obtained valid quorums.
5. In any execution, at most $f$ witnesses are Byzantine. Thus, the maximum number of Byzantine witnesses in the intersection $Q_1 \cap Q_2$ is at most $f$.
6. If $2k - n > f$, then:
   $$|Q_1 \cap Q_2| \ge 2k - n > f$$
7. Therefore, the intersection $Q_1 \cap Q_2$ contains at least one strictly honest witness $w^*$:
   $$w^* \in (Q_1 \cap Q_2) \setminus \mathcal{B}$$
   where $\mathcal{B}$ is the set of Byzantine witnesses.
8. By definition, an honest witness $w^*$ strictly enforces the C2SP protocol: it verifies Merkle consistency before cosigning and NEVER cosigns conflicting or backwards checkpoints.
9. Hence, $w^*$ could not have cosigned both $C_1$ and $C_2$.
10. This contradiction establishes that two conflicting checkpoints cannot simultaneously gather $k$ cosignatures. $\blacksquare$

### 3.2 Liveness Theorem: $k \le n - f$

> **Theorem 2 (Liveness).** If $k \le n - f$, the transparency log can always make progress and reach quorum despite up to $f$ crashed, unresponsive, or refusing Byzantine witnesses.

#### Proof:
1. The total number of witnesses is $n$.
2. Up to $f$ witnesses may fail, crash, or refuse to cosign.
3. The number of remaining active and honest witnesses is at least $n - f$.
4. If $k \le n - f$, the honest witnesses alone provide at least $k$ valid cosignatures.
5. Thus, the system can continuously finalize valid checkpoints without stalling. $\blacksquare$

### 3.3 Boundary Examples

| $n$ (Total) | $k$ (Quorum) | $f$ (Tolerated) | Safety ($2k - n > f$) | Liveness ($k \le n - f$) | Assessment |
|:---:|:---:|:---:|:---:|:---:|:---|
| 3 | 2 | 1 | $4 - 3 = 1 \ngtr 1$ ❌ | $2 \le 2$ ✅ | **Fail:** $f=1$ requires $2k-n \ge 2$, meaning $k=3$ for $n=3$, or $f=0$. For $n=3, k=2$, safe against $f=0$. |
| 4 | 3 | 1 | $6 - 4 = 2 > 1$ ✅ | $3 \le 3$ ✅ | **Optimal BFT:** Perfect safety and liveness with 1 faulty node. |
| 5 | 4 | 1 | $8 - 5 = 3 > 1$ ✅ | $4 \le 4$ ✅ | **Conservative:** High threshold, resilient against 1 failure. |
| 7 | 5 | 2 | $10 - 7 = 3 > 2$ ✅ | $5 \le 5$ ✅ | **Enterprise BFT:** Tolerates 2 malicious nodes simultaneously. |

---

## 4. Attack Scenarios & Mitigations

### 4.1 Split-View / Log Fork Attack
- **Attack:** The log produces Checkpoint $A$ (size 10, root $R_A$) for Client 1 and Checkpoint $B$ (size 10, root $R_B$) for Client 2.
- **Detection:**
  1. Witness nodes check previous tree heads. If a witness is asked to cosign $B$ after $A$, it detects $R_A \ne R_B$ at identical size and rejects the request.
  2. The Monitor continuously queries the log and witnesses. Upon observing both $A$ and $B$, it pairs their signatures and packages an `EvidenceBundle` of type `LogEquivocation`.
  3. The offline verifier proves the log signed two different roots for the same tree size.

### 4.2 Witness Rollback Attack
- **Attack:** An attacker gains root access to a witness host, stops the daemon, replaces `witness.db` with an older snapshot (e.g., size 5 instead of size 10), and restarts the witness. A malicious log then presents an alternate fork starting at size 6.
- **Detection:**
  1. The monitor detects that the witness cosigned size 10 at $T_1$, and later cosigned size 6 at $T_2$ ($T_2 > T_1$).
  2. The offline verifier inspects the timestamps and sizes: $S_2 < S_1$ signed by the same key proves a state regression (`WitnessRollback`).
  3. The witness is permanently blacklisted.

### 4.3 Witness Equivocation Attack
- **Attack:** A compromised witness intentionally cosigns two conflicting checkpoints for the same tree size to assist a malicious log operator.
- **Detection:**
  1. Any peer or monitor observing both cosignature lines constructs an `EvidenceBundle` of type `WitnessEquivocation`.
  2. The offline verifier checks the Ed25519 signature of the witness on both records.
  3. The Policy Engine revokes the witness key and records the event in the append-only audit log.

### 4.4 Sybil / Witness Collusion Attack
- **Attack:** An attacker attempts to introduce multiple malicious witnesses to reach quorum $k$.
- **Mitigation:**
  - Witness identity is strictly tied to out-of-band registered Ed25519 public keys.
  - Adding or removing witnesses requires an administrative policy transaction committed to the tamper-evident audit log. Dynamic admission without quorum agreement is rejected.

---

## 5. Trust Assumptions & Boundaries

1. **Cryptographic Primitives:** SHA-256 is collision-resistant and preimage-resistant. Ed25519 signatures are unforgeable under chosen-message attacks (EUF-CMA).
2. **Out-of-Band Root of Trust:** Clients and witnesses initially receive the log's legitimate Ed25519 public key and the initial witness roster through a trusted channel (e.g., software packaging, DNSSEC-anchored records, or manual configuration).
3. **Eventual Delivery:** Network partitions eventually heal, allowing gossip monitors to detect and publish equivocation proofs.

---

## 6. Support & Inquiries

For technical questions, cryptographic audits, or vulnerability disclosures, please contact:
- **Maintainer:** Rishi Kulkarni
- **GitHub:** [@geeky-rish](https://github.com/geeky-rish)
- **Email:** `chingi11@proton.me`
