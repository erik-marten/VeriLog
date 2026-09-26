/*
 * Copyright 2026 Erik Marten
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */
package io.github.em.verilog.logger;

import java.nio.file.Path;
import java.time.Instant;

final class RotationPolicy {
    final long rotateBytes;
    final String filePrefix;

    RotationPolicy(long rotateBytes, String filePrefix) {
        this.rotateBytes = rotateBytes;
        this.filePrefix = filePrefix;
    }

    Path rotatedPath(Path dir) {
        String ts = Instant.now().toString().replace(':', '-');
        String name = filePrefix + "-" + ts + ".vlog";
        return dir.resolve(name);
    }
}