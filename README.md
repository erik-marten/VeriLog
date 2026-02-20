# VeriLog 

**VeriLog** is a cryptographically verifiable, tamper-evident audit logging library **currently**  only for Java. A .NET equivalent plan is in breakdown.

It provides:

-  **Hash-chained audit entries**
- **ECDSA signatures (P-256)**
-  **Framed binary log format**
-  **Authenticated encryption (XChaCha20-Poly1305)**
- **Log rotation support**
- **End-to-end verification**

VeriLog is designed for systems that require **strong integrity guarantees**, such as:

- Security-sensitive applications
- Compliance logging
- Financial systems
- Infrastructure audit trails
- High-assurance backends

------

## Why VeriLog?

Traditional logs can be:

- Edited retroactively
- Reordered
- Truncated
- Forged

VeriLog prevents this by combining:

### Hash chaining

Each entry references the hash of the previous entry.

If one entry changes → the entire chain breaks.

### Digital signatures

Each entry is signed using ECDSA (P-256).

You can cryptographically prove:

- Who created the entry
- That it has not been modified

### Authenticated encryption

Log files are encrypted using XChaCha20-Poly1305.

This ensures:

- Confidentiality
- Integrity
- Tamper detection at file level

------

## Architecture Overview

```
Application
    ↓
SignedEntryFactory
    ↓
HashChainState
    ↓
FramedLogFile
    ↓
XChaCha20-Poly1305
    ↓
Disk
```

Each layer enforces a specific security property:

| Layer           | Guarantees                  |
| --------------- | --------------------------- |
| Hash chain      | Forward integrity           |
| ECDSA signature | Authenticity                |
| AEAD encryption | Confidentiality + integrity |
| Framing         | Structural validation       |

------

## Example (High-Level)

```java
VeriLogger logger = VeriLogger.builder()
    .logDir(Path.of("logs"))
    .encryptionKey(key32Bytes)
    .signer(signer)
    .build();

logger.log("user.login", Map.of(
    "userId", "1234",
    "ip", "10.0.0.5"
));
```

Later:

```java
VeriLogReader.verifyDirectory(Path.of("logs"));
```

If anything was modified, verification fails.

------

## Security Model

VeriLog assumes:

- The signing key is protected.
- The encryption key is protected.
- Attackers may have read/write access to log files.
- Attackers may attempt to:
  - Modify entries
  - Remove entries
  - Insert fake entries
  - Reorder entries

VeriLog guarantees detection of such tampering.

------

## Status

**!** Early stage.
APIs may change until `1.0.0`.
