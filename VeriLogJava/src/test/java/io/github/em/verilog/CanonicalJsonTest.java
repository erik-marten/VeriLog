package io.github.em.verilog;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class CanonicalJsonTest {

    @Test
    void should_sort_object_keys_lexicographically_and_removes_whitespace() throws Exception {
        String input = "{\n  \"b\": 2,\n  \"a\": 1,\n  \"c\": {\"y\": true, \"x\": null}\n}";
        String out = CanonicalJson.canonicalize(input);
        assertEquals("{\"a\":1,\"b\":2,\"c\":{\"x\":null,\"y\":true}}", out);
    }

    @Test
    void should_escape_control_characters() throws Exception {
        ObjectMapper om = new ObjectMapper();
        ObjectNode obj = om.createObjectNode();
        obj.put("k", "line1\nline2\t\u0001");

        String out = CanonicalJson.canonicalize(obj);
        // \n and \t should be escaped, and 0x01 should become a \u0001 escape.
        assertEquals("{\"k\":\"line1\\nline2\\t\\u0001\"}", out);
    }

    @Test
    void should_reject_floating_point_numbers() {
        assertThrows(IllegalArgumentException.class, () -> CanonicalJson.canonicalize("{\"x\": 1.25}"));
    }
}
