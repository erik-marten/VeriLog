package io.github.em.verilog.errors;

public final class VeriLogUncheckedException extends RuntimeException {
    public VeriLogUncheckedException(VeriLogException cause) {
        super(cause);
    }

    @Override
    public synchronized VeriLogException getCause() {
        return (VeriLogException) super.getCause();
    }
}