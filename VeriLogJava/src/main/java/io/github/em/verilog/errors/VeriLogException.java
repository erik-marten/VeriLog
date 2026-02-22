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

public class VeriLogException extends Exception {
    public enum Category {IO, FORMAT, JSON, CRYPTO, KEY, INTERNAL}

    private final Category category;
    private final String messageKey;
    private final Object[] messageArgs;

    public VeriLogException(Category category, String messageKey, Object... messageArgs) {
        super(ErrorMessages.format(messageKey, messageArgs));
        this.category = category;
        this.messageKey = messageKey;
        this.messageArgs = messageArgs == null ? new Object[0] : messageArgs.clone();
    }

    public VeriLogException(Category category, String messageKey, Throwable cause, Object... messageArgs) {
        super(ErrorMessages.format(messageKey, messageArgs), cause);
        this.category = category;
        this.messageKey = messageKey;
        this.messageArgs = messageArgs == null ? new Object[0] : messageArgs.clone();
    }

    public Category getCategory() {
        return category;
    }

    public String getMessageKey() {
        return messageKey;
    }

    public Object[] getMessageArgs() {
        return messageArgs.clone();
    }
}