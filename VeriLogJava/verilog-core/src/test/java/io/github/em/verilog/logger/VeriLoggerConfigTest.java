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

import io.github.em.verilog.logger.utils.TestConfigBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class VeriLoggerConfigTest {

    @TempDir
    Path tmp;

    @Test
    void should_reject_null_actor() throws Exception {
        NullPointerException error = assertThrows(
                NullPointerException.class,
                () -> TestConfigBuilder.configBuilder(tmp).actor(null).build()
        );

        assertEquals("actor", error.getMessage());
    }

    @Test
    void should_reject_blank_actor() throws Exception {
        IllegalArgumentException error = assertThrows(
                IllegalArgumentException.class,
                () -> TestConfigBuilder.configBuilder(tmp).actor(" \t\n").build()
        );

        assertEquals("actor must not be blank", error.getMessage());
    }
}
