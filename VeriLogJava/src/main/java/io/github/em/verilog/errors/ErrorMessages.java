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

import java.text.MessageFormat;
import java.util.Locale;
import java.util.MissingResourceException;
import java.util.ResourceBundle;

final class ErrorMessages {
    private static final String BUNDLE = "messages";

    private ErrorMessages() {}

    static String format(String key, Object... args) {
        return format(Locale.ROOT, key, args);
    }

    static String format(Locale locale, String key, Object... args) {
        try {
            ResourceBundle rb = ResourceBundle.getBundle(BUNDLE, locale);
            String pattern = rb.getString(key);
            return MessageFormat.format(pattern, args);
        } catch (MissingResourceException e) {
            // Safe fallback: prevent fail while trying to build an error message
            String fallback = key + (args != null && args.length > 0 ? " " + java.util.Arrays.toString(args) : "");
            return fallback;
        }
    }
}