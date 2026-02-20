package io.github.em.verilog;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

public final class CanonicalJson {
    private CanonicalJson() {}

    public static String canonicalize(String json) throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        JsonNode node = mapper.readTree(json);
        return canonicalize(node);
    }

    public static String canonicalize(JsonNode node) throws IOException {
        StringBuilder sb = new StringBuilder();
        writeNode(node, sb);
        return sb.toString();
    }

    private static void writeNode(JsonNode node, StringBuilder sb) {
        if (node.isObject()) {
            sb.append('{');
            ObjectNode obj = (ObjectNode) node;

            List<String> names = new ArrayList<>();
            obj.fieldNames().forEachRemaining(names::add);
            names.sort(Comparator.naturalOrder()); // lexicographic (Unicode code point order)

            for (int i = 0; i < names.size(); i++) {
                if (i > 0) sb.append(',');
                writeString(names.get(i), sb);
                sb.append(':');
                writeNode(obj.get(names.get(i)), sb);
            }
            sb.append('}');
            return;
        }

        if (node.isArray()) {
            sb.append('[');
            ArrayNode arr = (ArrayNode) node;
            for (int i = 0; i < arr.size(); i++) {
                if (i > 0) sb.append(',');
                writeNode(arr.get(i), sb);
            }
            sb.append(']');
            return;
        }

        if (node.isTextual()) { writeString(node.textValue(), sb); return; }

        if (node.isIntegralNumber()) {
            sb.append(node.longValue());
            return;
        }

        if (node.isFloatingPointNumber() || node.isBigDecimal()) {
            throw new IllegalArgumentException("Floating point numbers are not allowed in Canonical JSON.");
        }

        if (node.isBoolean()) { sb.append(node.booleanValue() ? "true" : "false"); return; }
        if (node.isNull()) { sb.append("null"); return; }

        throw new IllegalArgumentException("Unsupported JSON type: " + node.getNodeType());
    }

    private static void writeString(String s, StringBuilder sb) {
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char ch = s.charAt(i);
            switch (ch) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\b': sb.append("\\b"); break;
                case '\f': sb.append("\\f"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (ch <= 0x1F) sb.append(String.format("\\u%04x", (int) ch));
                    else sb.append(ch);
            }
        }
        sb.append('"');
    }
}