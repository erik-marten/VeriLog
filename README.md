# VeriLog 

[![SonarQube Cloud](https://sonarcloud.io/images/project_badges/sonarcloud-light.svg)](https://sonarcloud.io/summary/new_code?id=erik-marten_VeriLog)

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

## Java modules and build

The Gradle build lives in `VeriLogJava/` and contains three modules:

| Module | Contents |
| --- | --- |
| `verilog-core` | Framework-independent crypto, framing, signing, readers, verification, and errors. The existing custom logger remains here temporarily. |
| `verilog-cli` | The verification CLI, depending on `verilog-core`. |
| `verilog-logback` | A library module depending on `verilog-core`, reserved for future Logback integration. `VeriLogEncoder` is not implemented yet. |

`verilog-core` has no SLF4J or Logback dependency. Existing Java packages and the `.vlog` format are preserved.

Use JDK 17 or newer to run Gradle and install JDK 11 for compilation and tests. From the repository root:

```sh
./gradlew build
```

This builds all modules, runs their tests and coverage checks, and creates the executable CLI JAR at `VeriLogJava/verilog-cli/build/libs/verilog-cli-1.0-SNAPSHOT-all.jar`. The wrapper also works from `VeriLogJava/`.

Run verification through Gradle, replacing the example key and file values:

```sh
./gradlew :verilog-cli:run --args="verify --file logs/current.vlog --dek-hex <64-hex-digits> --pub public.pem"
```

Paths passed through Gradle are relative to `VeriLogJava/`, preserving the existing CLI launch behavior.

Or run the executable JAR with Java 11 or newer:

```sh
java -jar VeriLogJava/verilog-cli/build/libs/verilog-cli-1.0-SNAPSHOT-all.jar \
  verify --file logs/current.vlog --dek-hex "$VERILOG_DEK_HEX" --pub public.pem
```

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

-----

## License

Copyright 2026 Erik Marten

This project is licensed under the Apache License 2.0.

You may use, modify, and distribute this software in accordance with the License.
A copy of the License is provided in the LICENSE file.

This software provides cryptographic functionality. Users are responsible
for ensuring compliance with all applicable laws and regulations regarding
the use, distribution, and export of cryptographic software.

Distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND.
