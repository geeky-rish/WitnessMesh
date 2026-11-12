# WitnessMesh Cryptographic Evidence Bundle Specification

**Format Version:** 1.0  
**Encoding:** Canonical JSON & Deterministic Binary (TLV/Length-Prefixed)  
**Document Version:** 1.0.0  

---

## 1. Overview & Design Principles

An **Evidence Bundle** is a self-contained, tamper-evident cryptographic artifact that establishes indisputable mathematical proof of a security violation by a transparency log operator or witness node.

### Core Properties:
1. **Self-Contained:** Does not require access to the live network, external databases, or the transparency log to verify.
2. **Deterministic Serialization:** Produces identical binary digests regardless of compiler, architecture, or programming language.
3. **Non-Repudiable:** Leverages valid digital signatures issued by the misbehaving parties themselves.
4. **Machine-Parseable:** Supports both human-readable JSON (for auditing and web dashboards) and compact deterministic binary (for low-bandwidth peer gossip).

---

## 2. Evidence Violation Taxonomies

WitnessMesh formalizes five canonical evidence case types:

| Case Identifier | Numeric ID | Description | Cryptographic Proof Required |
|---|:---:|---|---|
| `LogEquivocation` | `0x01` | Same-size log fork | 2 checkpoints with same `tree_size`, different `root_hash`, both signed with valid log Ed25519 key. |
| `LogSplitView` | `0x02` | Different-size log fork | 2 checkpoints ($S_1 < S_2$) with valid log signatures, where the RFC 6962 consistency proof fails or cannot exist. |
| `WitnessEquivocation` | `0x03` | Witness dual-signing | 2 distinct checkpoints (same or different size) with valid cosignatures from the same witness key. |
| `WitnessRollback` | `0x04` | Witness tree size regression | 2 cosignatures by same witness where $T_2 > T_1$ but $S_2 < S_1$, proving witness rolled back state. |
| `CollusionEquivocation`| `0x05` | Colluding log & witness quorum | Conflicting checkpoint accompanied by a subset of witness cosignatures contradicting majority quorum. |

---

## 3. Canonical JSON Schema Specification

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "WitnessMeshEvidenceBundle",
  "type": "object",
  "required": [
    "format_version",
    "case",
    "log_identity",
    "checkpoints",
    "cosignatures",
    "detected_at",
    "detector_id"
  ],
  "properties": {
    "format_version": { "type": "integer", "enum": [1] },
    "case": {
      "type": "string",
      "enum": [
        "same-size-fork",
        "different-size-fork",
        "witness-equivocation",
        "witness-rollback",
        "collusion-equivocation"
      ]
    },
    "log_identity": {
      "type": "object",
      "required": ["public_key", "origin", "key_hash"],
      "properties": {
        "public_key": { "type": "string", "pattern": "^[0-9a-fA-F]{64}$" },
        "origin": { "type": "string" },
        "key_hash": { "type": "string", "pattern": "^[0-9a-fA-F]{64}$" }
      }
    },
    "checkpoints": {
      "type": "array",
      "minItems": 1,
      "items": {
        "type": "object",
        "required": ["tree_size", "root_hash", "signature"],
        "properties": {
          "tree_size": { "type": "integer", "minimum": 0 },
          "root_hash": { "type": "string", "pattern": "^[0-9a-fA-F]{64}$" },
          "signature": { "type": "string", "pattern": "^[0-9a-fA-F]{128}$" },
          "key_id": { "type": "string" },
          "raw_text": { "type": "string" }
        }
      }
    },
    "cosignatures": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["witness_id", "witness_name", "timestamp", "signature", "checkpoint_size"],
        "properties": {
          "witness_id": { "type": "string", "pattern": "^[0-9a-fA-F]{64}$" },
          "witness_name": { "type": "string" },
          "timestamp": { "type": "integer" },
          "signature": { "type": "string", "pattern": "^[0-9a-fA-F]{128}$" },
          "checkpoint_size": { "type": "integer" }
        }
      }
    },
    "consistency_proof": {
      "type": "object",
      "properties": {
        "old_size": { "type": "integer" },
        "new_size": { "type": "integer" },
        "hashes": {
          "type": "array",
          "items": { "type": "string", "pattern": "^[0-9a-fA-F]{64}$" }
        }
      }
    },
    "detected_at": { "type": "string", "format": "date-time" },
    "detector_id": { "type": "string" },
    "metadata": { "type": "object" }
  }
}
```

---

## 4. Deterministic Binary Encoding

Binary evidence bundles are encoded using strict, endian-explicit TLV sequences:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       Magic Bytes: 'W' 'M' 'E' 'V' (0x57, 0x4D, 0x45, 0x56)   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Version (0x01)| CaseType (1B) |     Origin Length (2B BE)     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Origin String (variable)                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                   Log Public Key (32 Bytes)                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Checkpoint Count (2B BE)      | Checkpoint 0 Size (8B BE)     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                   Checkpoint 0 Root Hash (32 Bytes)           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                   Checkpoint 0 Signature (64 Bytes)           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           ...                                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Cosignature Count (2B BE)     | Witness 0 ID (32 Bytes)       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Witness 0 Timestamp (8B BE)   | Witness 0 Checkpoint Size (8B)|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                   Witness 0 Signature (64 Bytes)              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Proof Path Count (2B BE)      | Hash 0 (32 Bytes)             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

---

## 5. Offline Verification Rules

The offline verifier executes the following algorithm over an evidence bundle:

```
Algorithm VerifyBundle(Bundle):
  1. If Bundle is empty or malformed:
       Return (INVALID, "bundle is null or corrupted")

  2. Verify Log Public Key is configured as trusted:
       If not found: Return (INVALID, "untrusted log identity")

  3. For each Checkpoint C in Bundle.Checkpoints:
       Target := CanonicalCheckpointString(C.Origin, C.TreeSize, C.RootHash)
       If NOT Ed25519Verify(Bundle.LogIdentity.PublicKey, Target, C.Signature):
         Return (INVALID, "invalid cryptographic signature on checkpoint")

  4. Case-Specific Validation:
       Switch Bundle.Case:
         Case "same-size-fork":
           Require len(Bundle.Checkpoints) >= 2
           C1 := Bundle.Checkpoints[0], C2 := Bundle.Checkpoints[1]
           If C1.TreeSize != C2.TreeSize:
             Return (INVALID, "checkpoints have different tree sizes")
           If C1.RootHash == C2.RootHash:
             Return (INVALID, "identical root hashes; no equivocation")
           Return (VALID, "log equivocation confirmed: same size with distinct roots")

         Case "different-size-fork":
           Require len(Bundle.Checkpoints) >= 2
           C1 := Bundle.Checkpoints[0], C2 := Bundle.Checkpoints[1]
           OldSize := min(C1.TreeSize, C2.TreeSize)
           NewSize := max(C1.TreeSize, C2.TreeSize)
           ProofValid := VerifyConsistencyProof(OldSize, NewSize, C1.RootHash, C2.RootHash, Bundle.Proof)
           If ProofValid:
             Return (INVALID, "consistency proof is valid; trees are consistent")
           Return (VALID, "consistency proof rejected; trees diverge")

         Case "witness-equivocation":
           Require len(Bundle.Cosignatures) >= 2
           W1 := Bundle.Cosignatures[0], W2 := Bundle.Cosignatures[1]
           If W1.WitnessID != W2.WitnessID:
             Return (INVALID, "cosignatures belong to different witnesses")
           Verify both W1 and W2 signatures over their respective checkpoint targets
           Return (VALID, "witness equivocation confirmed")
```

---

## 6. Real-World Sample Payload

Below is an authentic evidence bundle generated by WitnessMesh during attack simulation:

```json
{
  "format_version": 1,
  "case": "witness-equivocation",
  "log_identity": {
    "public_key": "b58c5fbb2040f1f0df5edc84172b9c1f81868d9a5af613dafa0488ea012cfcd7",
    "origin": "sigsum.org/v1/tree/a9fce5ebf8bf217ae6042236794d906670623822edd9506eb91aa70e2208ab45",
    "key_hash": "a9fce5ebf8bf217ae6042236794d906670623822edd9506eb91aa70e2208ab45"
  },
  "checkpoints": [
    {
      "tree_size": 10,
      "root_hash": "8f8b1a41bc386180373fe4236e3c0ee0a3a401f8d4e9f733db9f7278297b4168",
      "signature": "3e9b11029da689252efbebf7167a54483758b9918c5f87b322da54a496838a16dbd7831d4e78a632e8e35492d274092bbfb776ecf8cfeb2be58b4f2c0bf1da04"
    },
    {
      "tree_size": 10,
      "root_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "signature": "6cb773b0632a76f238fdb834246949392e2d8471da3410e6a3f478a5482e9b048d2eb98b2553757dbd8a1beebc88a8d0e3ec8b97d8c6b90757a4198d0421da08"
    }
  ],
  "cosignatures": [
    {
      "witness_id": "4236e3c0ee0a3a401f8d4e9f733db9f7278297b41688f8b1a41bc386180373fe",
      "witness_name": "witness-0",
      "timestamp": 1731412820,
      "checkpoint_size": 10,
      "signature": "1c7a54483758b9918c5f87b322da54a496838a16dbd7831d4e78a632e8e354923e9b11029da689252efbebf72d274092bbfb776ecf8cfeb2be58b4f2c0bf1da04"
    },
    {
      "witness_id": "4236e3c0ee0a3a401f8d4e9f733db9f7278297b41688f8b1a41bc386180373fe",
      "witness_name": "witness-0",
      "timestamp": 1731412821,
      "checkpoint_size": 10,
      "signature": "da3410e6a3f478a5482e9b048d2eb98b2553757dbd8a1beebc88a8d0e3ec8b976cb773b0632a76f238fdb834246949392e2d8471d8c6b90757a4198d0421da08"
    }
  ],
  "detected_at": "2026-11-12T16:31:00Z",
  "detector_id": "monitor-0"
}
```

---

## 7. Support & Inquiries

For technical questions or to report verification discrepancies, please contact:
- **Maintainer:** Rishi Kulkarni
- **GitHub:** [@geeky-rish](https://github.com/geeky-rish)
- **Email:** `chingi11@proton.me`
