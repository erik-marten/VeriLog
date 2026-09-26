# ADR-0001: Use SLF4J and Logback as the logging runtime

- **Status:** Proposed
- **Date:** 2026-09-26

## Context

VeriLog provides cryptographically verifiable, tamper-evident logging. Its differentiating responsibilities are canonicalization, hash chaining, digital signatures, authenticated encryption, framing, and verification.

The current Java implementation also owns general logging-runtime concerns such as logging levels, queues, backpressure, writer threads, shutdown hooks, flushing, rotation, lifecycle, and logger metrics. These concerns increase implementation and maintenance surface without directly contributing to VeriLog's cryptographic value proposition.

The desired architecture is to rely on the established Java logging ecosystem for logging behavior and make VeriLog a cryptographic extension of that pipeline.

SLF4J is the application-facing logging API. A concrete backend, initially Logback, owns normal logging behavior such as event dispatch, filtering, appenders, file lifecycle, rotation, retention, and optional asynchronous processing.

VeriLog operates at the backend output/encoding boundary and transforms logging events into a cryptographically protected format.

## Decision

VeriLog will no longer implement its own general-purpose logging runtime.

Applications will log through SLF4J. The first supported backend integration will be Logback.

VeriLog will provide a Logback integration component that receives Logback logging events and converts selected events into VeriLog's cryptographically protected representation.

Conceptually:

```text
Application
    |
    v
  SLF4J
    |
    v
 Logback
    |
    +----------------------> normal appenders
    |
    v
 VeriLog integration
    |
    v
 Canonicalization
    |
    v
 Hash chain
    |
    v
 Signature
    |
    v
 Authenticated encryption
    |
    v
 VeriLog frame bytes
    |
    v
 Logback output / file lifecycle
```

## Responsibility boundary

### SLF4J / Logback own

- logger names,
- logging levels,
- filtering,
- parameterized messages,
- exceptions,
- MDC,
- appender lifecycle,
- normal file handling,
- rotation and retention,
- optional asynchronous dispatch,
- logging configuration.

### VeriLog owns

- mapping selected logging events into a stable cryptographic event representation,
- canonical serialization,
- sequence and chain semantics,
- hash chaining,
- digital signatures,
- authenticated encryption,
- VeriLog framing,
- cryptographic verification,
- key handling required by these operations.

## Security boundary

The logging framework is not allowed to determine cryptographically relevant bytes after an event crosses the VeriLog integration boundary.

VeriLog exclusively determines:

- canonical bytes,
- sequence allocation,
- previous-hash values,
- entry hashes,
- signature input,
- cryptographic signatures,
- encryption nonces and AEAD construction,
- frame representation,
- verification rules.

Logback is responsible for delivering events to the VeriLog integration and for the configured output lifecycle. VeriLog does not claim stronger event-delivery guarantees than the selected logging-backend configuration provides.

## Event selection

Not every ordinary application log event is automatically an audit event.

VeriLog integrations SHOULD provide an explicit opt-in mechanism, such as a marker, dedicated logger name, filter, structured attribute, or another clearly documented selection mechanism.

Logging levels such as `INFO`, `WARN`, and `ERROR` are not security-domain event types.

## Delivery semantics

VeriLog guarantees the cryptographic integrity of events delivered to its integration component and successfully encoded by VeriLog.

Delivery before that boundary is controlled by SLF4J/Logback configuration.

For example, asynchronous or lossy backend configurations may discard events before VeriLog sees them. Such configurations MUST NOT be represented as providing lossless audit delivery.

Where an application requires a business operation to fail if its audit record cannot be produced, a stronger direct VeriLog API may be provided separately. This does not change the logging-runtime decision in this ADR.

## Module direction

The target structure is:

```text
verilog-core
    canonicalization
    crypto
    chaining
    framing
    verification
    key handling

verilog-logback
    Logback event mapping
    VeriLog encoder/appender integration
    event-selection helpers

verilog-cli
    verification and inspection tooling
```

`verilog-core` MUST NOT depend on SLF4J, Logback, or Log4j.

`verilog-logback` depends on `verilog-core`.

Additional backend integrations, such as Log4j2, may be added later without changing the core cryptographic model.

## Existing implementation

The following current general logging-runtime components are candidates for removal or substantial redesign:

- `VeriLogger`
- `LogEvent`
- `BackpressureEnqueuer`
- `LogWriter`
- `FlushPolicy`
- `RotationPolicy`
- `LoggerMetrics`
- logging-runtime portions of `VeriLoggerConfig`

The following areas remain central to VeriLog and should be preserved or refactored into `verilog-core`:

- `CanonicalJson`
- `CryptoUtil`
- `EcdsaSigCodec`
- `HashChainState`
- `SignedEntryFactory`
- cryptographic primitives
- framing logic that is part of the VeriLog format
- reader and verification logic
- signing and key infrastructure
- VeriLog-specific errors

## Consequences

### Positive

- Smaller VeriLog-owned logging surface.
- Less custom lifecycle, threading, rotation, and backpressure code.
- Lower maintenance burden for non-cryptographic behavior.
- Cleaner security boundary.
- Easier integration into existing Java applications.
- Core cryptographic code remains backend-independent.

### Negative

- The first integration is backend-specific because SLF4J itself does not define appenders or file-output extension points.
- Security documentation must distinguish cryptographic integrity from event-delivery guarantees.
- Backend configuration can affect whether events reach VeriLog.
- Migration from the current `VeriLogger` API is a breaking change.

## Compatibility

This architectural decision does not automatically authorize changes to the existing VeriLog cryptographic format.

Any change to canonicalization, signed fields, hash-chain semantics, framing, authenticated encryption, or verification rules requires separate review and explicit version handling.

## Migration strategy

The migration will be incremental:

1. Extract cryptographic/event-format responsibilities into a backend-independent core.
2. Introduce the Logback integration on top of that core.
3. Move logging-runtime behavior to Logback configuration.
4. Remove or deprecate the current custom logging runtime.
5. Update examples and documentation to use SLF4J plus Logback.
6. Review chain continuity, restart recovery, rotation boundaries, and delivery claims before `1.0.0`.

## Open questions

The following questions remain implementation decisions and may require follow-up ADRs:

- Which Logback extension point should be primary: encoder, appender, or a combination?
- How are audit events selected explicitly?
- Which MDC or structured fields may enter signed content?
- How is chain state recovered after restart?
- How is chain continuity represented across file rotation performed by Logback?
- What exact guarantees are documented for synchronous versus asynchronous backend configurations?
