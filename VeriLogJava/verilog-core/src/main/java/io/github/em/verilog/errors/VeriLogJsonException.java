/*
 * Copyright 2026 Erik Marten
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */
package io.github.em.verilog.errors;

public class VeriLogJsonException extends VeriLogException {
    public VeriLogJsonException(String key, Object... args) {
        super(Category.JSON, key, args);
    }
    public VeriLogJsonException(String key, Throwable cause, Object... args) {
        super(Category.JSON, key, cause, args);
    }
}
