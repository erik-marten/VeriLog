/*
 * Copyright 2026 Erik Marten
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */
package io.github.em.verilog.reader;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public final class DirectoryVerifyReport {

    public static final class FileResult {
        public final Path file;
        public final boolean ok;
        public final long lastSeqOrFailSeq;
        public final String reason; // null if ok

        public FileResult(Path file, boolean ok, long lastSeqOrFailSeq, String reason) {
            this.file = file;
            this.ok = ok;
            this.lastSeqOrFailSeq = lastSeqOrFailSeq;
            this.reason = reason;
        }
    }

    private final List<FileResult> results = new ArrayList<>();

    void add(FileResult r) { results.add(r); }

    public List<FileResult> results() {
        return Collections.unmodifiableList(results);
    }

    public boolean allOk() {
        for (FileResult r : results) if (!r.ok) return false;
        return true;
    }
}