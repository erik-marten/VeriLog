package io.github.em.verilog.errors;

import org.junit.jupiter.api.Test;

import java.util.Locale;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class ErrorMessagesTest {
    @Test
    void should_return_key_when_resource_missing_and_no_args() {
        String result = ErrorMessages.format(Locale.ROOT, "non.existing.key");

        assertEquals("non.existing.key", result);
    }

    @Test
    void should_append_args_when_resource_missing_and_args_present() {
        String result = ErrorMessages.format(
                Locale.ROOT,
                "non.existing.key",
                "foo",
                42
        );

        assertEquals("non.existing.key [foo, 42]", result);
    }
}
