# SLF4J / Logback example

This runnable application shows the current VeriLog integration: ordinary SLF4J calls go through Logback, and `VeriLogRollingFileAppender` writes only events explicitly marked as audit events. It uses the `verilog-core` and `verilog-logback` source projects through a Gradle composite build; no copied JARs or Maven Local publication are needed.

From the repository root, run:

```sh
./VeriLogJava/gradlew -p examples/LogbackExample clean run
```

`clean` removes the previous demo chain before new, random keys are generated. The run compiles the example, writes `examples/LogbackExample/build/verilog-logs/current.vlog`, stops Logback, and verifies the full output directory. Expected application output:

```text
VeriLog verification succeeded.
Verified audit entries: 2
```

The application emits an ordinary `logger.info("Application started")` and two explicit audit events. An audit event uses SLF4J 2 key/value metadata:

```java
logger.atInfo()
        .addKeyValue("verilog.eventType", "USER_LOGIN")
        .log("User {} logged in", "alice");
```

The other event has type `USER_LOGOUT`. `INFO` is only the Logback severity level; it is never used as `eventType`. The unmarked startup message creates no VeriLog frame.

The P-256 signing key pair and 32-byte DEK are generated in memory for each run. This is demo material: the example neither persists nor prints it, so a later process cannot decrypt or verify these logs. Production applications must supply durable, protected keys and retain the matching public keys for verification. The current integration is bootstrapped programmatically because its signer, public-key resolver, and DEK are typed security objects; XML-only bootstrap is a separate design task. An isolated `LoggerContext` also needs a Logback MDC adapter so ordinary logging events expose MDC metadata to the integration.

One JVM must own each logical chain. Keep `append=true`, `prudent=false`, and uncompressed `.vlog` rotation. Retain the active file and every rotated file from the chain root for restart recovery; do not enable bounded retention that deletes that history. The example uses a normal size-and-time rolling policy without compression or a retention bound, and does not depend on a rollover occurring during its short run. Logging filters, routing, or upstream asynchronous components can discard events before they reach VeriLog, so the cryptographic guarantee starts at the integration boundary.
