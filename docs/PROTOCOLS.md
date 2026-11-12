# WitnessMesh Cryptographic Protocols Specification

**Standards Compliance:** RFC 6962, RFC 9162, C2SP `tlog-witness`  
**Cryptographic Primitives:** Ed25519 (RFC 8032), SHA-256 (FIPS 180-4)  
**Document Version:** 1.0.0  

---

## 1. Overview & Primitives

WitnessMesh implements standardized cryptographic protocols for transparency log verification and distributed witness cosigning. All cryptographic operations use strict domain separation to prevent collision and extension attacks.

| Primitive | Implementation / Algorithm | Parameter / Purpose |
|---|---|---|
| **Digital Signatures** | Ed25519 (`crypto/ed25519`) | Checkpoint & Cosignature generation (64-byte signatures, 32-byte public keys) |
| **Cryptographic Hash** | SHA-256 (`crypto.HashBytes`) | Merkle tree hashing, node prefixes, audit log chaining |
| **Key Identity Hash** | SHA-256 over raw Ed25519 public key | 32-byte canonical identifier for logs and witnesses |
| **Merkle Tree Proofs** | RFC 6962 / RFC 9162 standard | Inclusion and consistency verification |

---

## 2. Merkle Tree Construction (RFC 6962)

### 2.1 Domain Separation
To prevent interior nodes from being interpreted as leaf nodes (and vice-versa), hashes prepend distinct one-byte domain separation prefixes:
- **Leaf Node Hash:**
  $$H_{\text{leaf}}(M) = \text{SHA-256}(\text{0x00} \parallel M)$$
- **Interior Node Hash:**
  $$H_{\text{interior}}(L, R) = \text{SHA-256}(\text{0x01} \parallel L \parallel R)$$
- **Empty Tree Root:**
  $$H_{\text{empty}} = \text{SHA-256}(\text{""})$$

### 2.2 Tree Computation Algorithm
For a list of $n$ leaves $[L_0, L_1, \dots, L_{n-1}]$:
1. If $n = 0$, return $H_{\text{empty}}$.
2. If $n = 1$, return $H_{\text{leaf}}(L_0)$.
3. For $n > 1$, partition at $k$, where $k$ is the largest power of two strictly less than $n$ ($k = 2^{\lfloor \log_2(n-1) \rfloor}$):
   $$\text{MTH}(L) = H_{\text{interior}}(\text{MTH}(L[0..k]), \text{MTH}(L[k..n]))$$

### 2.3 Consistency Proof Verification
A consistency proof between tree size $m$ and tree size $n$ ($m < n$) demonstrates that the first $m$ leaves of the newer tree are identical to the older tree.
- Verification follows RFC 6962 §2.1.2:
  1. If $m = n$, the proof is empty; roots must be identical.
  2. For $m < n$, let $k$ be the largest power of 2 strictly less than $n$.
  3. If $m \le k$, the path proves consistency between $m$ and $k$, with the right subtree hash completing the new root.
  4. If $m > k$, the path proves consistency between $m - k$ and $n - k$, using the left subtree hash ($m$-prefix) to complete both roots.
- All consistency proofs in WitnessMesh are verified via `sigsum.org/sigsum-go/pkg/merkle.VerifyConsistency`.

---

## 3. C2SP `tlog-witness` Protocol

WitnessMesh witnesses adhere to the C2SP (Community Cryptography Specification Project) `tlog-witness` protocol.

### 3.1 Endpoint: `POST /add-checkpoint`

Logs submit checkpoints to witnesses for verification and cosigning.

#### Request Format
The HTTP request body consists of:
1. An integer specifying the witness's previously verified tree size ($S_{\text{old}}$).
2. Followed by zero or more base64-encoded SHA-256 hashes representing the consistency proof from $S_{\text{old}}$ to $S_{\text{new}}$.
3. An empty line delimiter.
4. The signed checkpoint text.

```http
POST /add-checkpoint HTTP/1.1
Host: witness-0:8082
Content-Type: text/plain

1230
dGhpcyBpcyBhIHNhbXBsZSBoYXNoIDE=
YW5vdGhlciBzYW1wbGUgaGFzaCAy...

sigsum.org/v1/tree/a9fce5ebf8bf217ae6042236794d906670623822edd9506eb91aa70e2208ab45
1234
CsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=

— sigsum.org/v1/tree/a9fce5ebf8bf217ae6042236794d906670623822edd9506eb91aa70e2208ab45 qp38...
```

#### Verification Pipeline on Witness
Upon receipt, the witness executes:
1. **Origin Verification:** Confirms that the checkpoint origin string matches the configured log identity.
2. **Signature Verification:** Verifies the log's Ed25519 signature over the checkpoint lines (`origin \n size \n root_hash \n`).
3. **Monotonicity Check:**
   - Retrieve stored local state $(S_{\text{local}}, R_{\text{local}})$.
   - If $S_{\text{new}} < S_{\text{local}}$: Reject HTTP 409 (Backwards regression attempt).
   - If $S_{\text{new}} = S_{\text{local}}$:
     - If $R_{\text{new}} = R_{\text{local}}$: Return existing cosignature (Idempotent replay).
     - If $R_{\text{new}} \ne R_{\text{local}}$: Reject HTTP 409 (Equivocation detected).
   - If $S_{\text{new}} > S_{\text{local}}$:
     - Check consistency proof hashes from $S_{\text{local}}$ to $S_{\text{new}}$.
     - If consistency fails: Reject HTTP 400 (Invalid Merkle proof).
4. **State Persistence:**
   - Atomically persist $(S_{\text{new}}, R_{\text{new}})$ to SQLite inside an immediate write transaction.
5. **Cosignature Issuance:**
   - Generate Ed25519 signature over the cosignature statement:
     $$\text{CosignTarget} = \text{Origin} \parallel \text{TreeSize} \parallel \text{RootHash} \parallel \text{Timestamp}$$
   - Return HTTP 200 with the formatted cosignature line.

#### Response Format
```http
HTTP/1.1 200 OK
Content-Type: text/plain

— sigsum.org/v1/tree/a9fce5ebf8bf217ae6042236794d906670623822edd9506eb91aa70e2208ab45 cosignature/v1
time 1731412800
qg3k0bLp1rK8...
```

---

## 4. Gossip & Anomaly Detection Protocol

The background monitoring daemon executes continuous gossip:
1. **Periodic Polling:** Queries `/tree-head` from the transparency log and `/get-checkpoint` from all registered witnesses every $T_{\text{poll}}$ seconds.
2. **State Harmonization:** Evaluates all observed `(origin, tree_size, root_hash)` tuples.
3. **Anomaly Triggers:**
   - **Fork Trigger:** If $\exists \, C_1, C_2$ with $C_1.\text{size} = C_2.\text{size}$ and $C_1.\text{root} \ne C_2.\text{root}$.
   - **Consistency Failure:** If $\exists \, C_1.\text{size} < C_2.\text{size}$ and the log cannot supply a valid consistency proof.
   - **Equivocation Trigger:** If $\exists$ witness $W$ signing conflicting checkpoints.
4. **Action:** Assemble an `EvidenceBundle` containing raw checkpoints, signatures, and proofs, and push to `/api/incidents` and `/api/evidence`.

---

## 5. Support & Inquiries

For technical questions or protocol extensions, please contact:
- **Maintainer:** Rishi Kulkarni
- **GitHub:** [@geeky-rish](https://github.com/geeky-rish)
- **Email:** `chingi11@proton.me`
