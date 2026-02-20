package io.github.em.verilog.cli;

public final class VeriLogCli {
    public static void main(String[] args) {
        int code = new VerifyCommand().run(args);
        System.exit(code);
    }
}