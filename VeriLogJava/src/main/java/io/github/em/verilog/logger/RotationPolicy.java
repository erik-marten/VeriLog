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