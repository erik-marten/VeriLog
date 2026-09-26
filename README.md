# VeriLog

[![SonarQube Cloud](https://sonarcloud.io/images/project_badges/sonarcloud-light.svg)](https://sonarcloud.io/summary/new_code?id=erik-marten_VeriLog)

VeriLog is a Java library for cryptographically verifiable audit logs. It signs P-256 audit entries, links them with a hash chain, frames them in `.vlog` files, and encrypts them with XChaCha20-Poly1305. A reader verifies signatures, sequence and chain continuity, and authenticated encryption across the available files.

## Java modules and build

The Gradle build lives in `VeriLogJava/`:

| Module | Purpose |
| --- | --- |
| `verilog-core` | Framework-independent cryptography, framing, signing, chain state, and verification. |
| `verilog-logback` | Implemented SLF4J/Logback integration. `VeriLogRollingFileAppender` manages recovery and Logback file rotation; `VeriLogEncoder` converts marked events into signed and encrypted frames. |
| `verilog-cli` | Command-line verification using `verilog-core`. |

`verilog-core` has no SLF4J or Logback dependency. Use JDK 17 or newer to run Gradle and install JDK 11 for compilation and tests. From the repository root:

```sh
./gradlew clean build
```

The build runs the module tests and coverage checks and creates an executable CLI JAR at `VeriLogJava/verilog-cli/build/libs/verilog-cli-1.0-SNAPSHOT-all.jar`. For a complete, runnable logging and verification bootstrap, see [`examples/LogbackExample`](examples/LogbackExample/README.md).

To verify an existing chain with the CLI, provide its protected DEK and the corresponding public key:

```sh
java -jar VeriLogJava/verilog-cli/build/libs/verilog-cli-1.0-SNAPSHOT-all.jar \
  verify --dir logs --dek-hex "$VERILOG_DEK_HEX" --pub public.pem
```

## Architecture

```text
Application
    ↓
SLF4J
    ↓
Logback
    ↓
VeriLogRollingFileAppender
    ↓
VeriLogEncoder
    ↓
AuditEvent
    ↓
sign + hash-chain + encrypt
    ↓
Logback-managed .vlog files
```

Logback owns logging. VeriLog owns cryptography. The appender recovers and verifies the local chain before opening the active file. Its managed encoder signs and encrypts explicitly marked events, while Logback controls the rolling file lifecycle.

## Application usage

After programmatic bootstrap attaches the VeriLog appender to the corresponding Logback logger, application code obtains its logger through SLF4J. An unmarked call remains an ordinary log event and produces no VeriLog frame:

```java
org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger("example-service");
logger.info("Application started");

logger.atInfo()
        .addKeyValue("verilog.eventType", "USER_LOGIN")
        .log("User {} logged in", username);
```

Configure `VeriLogRollingFileAppender` programmatically with a producer actor, signer, public-key resolver, 32-byte DEK, AAD prefix, active `.vlog` file, and a started Logback rolling policy. The appender creates and configures `VeriLogEncoder`; application code does not configure that encoder directly. The [runnable example](examples/LogbackExample/README.md) shows the complete bootstrap and directory verification.

The audit semantics are explicit:

| Field | Meaning |
| --- | --- |
| `actor` | Static producer/service identity configured on the integration. It is not inferred from logger name, thread, MDC, log level, or message. |
| `eventType` | The value of explicit SLF4J 2 key/value metadata named `verilog.eventType`. Only events with that metadata become VeriLog entries. |
| `level` | Normal Logback severity metadata, such as `INFO`. It is not a security semantic and never supplies `eventType`. |

Security material is currently supplied as typed Java objects during programmatic Logback bootstrap. An XML-only configuration cannot provide those objects with the current API; XML-only bootstrap remains a separate design task.

## Security boundary and lifecycle

The cryptographic guarantee starts when an event reaches the VeriLog integration. Events removed earlier by Logback filters or routing, or by upstream asynchronous behavior, never enter the cryptographic chain. Operators must account for those paths when deciding which events must be audited.

Use a single JVM per logical chain, `append=true`, `prudent=false`, and uncompressed `.vlog` rotation. Restart recovery needs the full local chain history from sequence 1: both the active file and every rotated chain file must remain available. Do not configure bounded retention that deletes the chain root. The appender verifies that history on startup and repairs an incomplete tail only in the active file.

VeriLog detects mutation of existing material and insertion or reordering of chain entries. It detects internal deletion when later chain material remains. A whole-set rollback to an older valid prefix cannot be detected by the local chain alone; that requires external trusted state. Trusted anchors or checkpoints are a future solution for rollback detection.

Protect the signing key and DEK, and preserve the public keys needed to verify historical entries. The example generates fresh in-memory keys only to demonstrate the integration; production key storage and rotation are application responsibilities.

## Status

The project is pre-1.0; APIs may change before `1.0.0`.

## License

Copyright 2026 Erik Marten.

This project is licensed under the Apache License 2.0. See [LICENSE](LICENSE). This software provides cryptographic functionality. Users are responsible for ensuring compliance with applicable laws and regulations concerning its use, distribution, and export.

Distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND.
