// Transaction receipt-producing write-back adapter for Angerona.
//@category REAgent

import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.parser.FunctionSignatureParser;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public class GhidraWriteback extends GhidraScript {
    private static final class Mutation {
        String kind;
        Address address;
        boolean repeatable;
        String value;
        Mutation(String kind, Address address, boolean repeatable, String value) {
            this.kind = kind; this.address = address; this.repeatable = repeatable; this.value = value;
        }
    }

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2) {
            throw new IllegalArgumentException("usage: GhidraWriteback.java plan.tsv receipt.tsv");
        }
        List<String> rows = Files.readAllLines(Path.of(args[0]), StandardCharsets.UTF_8);
        String expectedHash = null;
        String planId = null;
        List<Mutation> mutations = new ArrayList<>();
        for (String row : rows) {
            String[] fields = row.split("\\t", -1);
            if (fields.length == 2 && fields[0].equals("target_sha256")) expectedHash = fields[1];
            else if (fields.length == 2 && fields[0].equals("plan_id")) planId = fields[1];
            else if (fields.length == 5 && fields[0].equals("mutation")) {
                Address address = currentProgram.getAddressFactory().getAddress(fields[2]);
                if (address == null) throw new IllegalArgumentException("invalid address " + fields[2]);
                String value = new String(Base64.getDecoder().decode(fields[4]), StandardCharsets.UTF_8);
                mutations.add(new Mutation(fields[1], address, fields[3].equals("1"), value));
            }
        }
        String actualHash = currentProgram.getExecutableSHA256();
        if (expectedHash == null || actualHash == null || !expectedHash.equalsIgnoreCase(actualHash)) {
            throw new IllegalStateException("write-back target hash mismatch");
        }
        int transaction = currentProgram.startTransaction("Angerona write-back " + planId);
        boolean commit = false;
        List<String> receipt = new ArrayList<>();
        receipt.add("plan_id\t" + planId);
        try {
            for (Mutation mutation : mutations) {
                String oldValue = readValue(mutation);
                applyMutation(mutation);
                String encoded = Base64.getEncoder().encodeToString(oldValue.getBytes(StandardCharsets.UTF_8));
                receipt.add("applied\t" + mutation.kind + "\t" + mutation.address + "\t" +
                    (mutation.repeatable ? "1" : "0") + "\t" + encoded);
            }
            commit = true;
            receipt.add("status\tapplied");
        }
        finally {
            currentProgram.endTransaction(transaction, commit);
            if (!commit) receipt.add("status\trolled_back");
            Files.write(Path.of(args[1]), receipt, StandardCharsets.UTF_8);
        }
    }

    private String readValue(Mutation mutation) throws Exception {
        Function function = currentProgram.getFunctionManager().getFunctionContaining(mutation.address);
        if (mutation.kind.equals("rename")) return function == null ? "" : function.getName();
        if (mutation.kind.equals("comment")) {
            int type = mutation.repeatable ? CodeUnit.REPEATABLE_COMMENT : CodeUnit.PRE_COMMENT;
            String value = currentProgram.getListing().getComment(type, mutation.address);
            return value == null ? "" : value;
        }
        if (mutation.kind.equals("type")) return function == null ? "" : function.getSignature().getPrototypeString();
        if (mutation.kind.equals("patch")) {
            byte[] buffer = new byte[decodeHex(mutation.value).length];
            int read = currentProgram.getMemory().getBytes(mutation.address, buffer);
            if (read != buffer.length) {
                throw new IllegalStateException("short read at " + mutation.address);
            }
            StringBuilder hex = new StringBuilder(buffer.length * 2);
            for (byte b : buffer) hex.append(String.format("%02x", b & 0xff));
            return hex.toString();
        }
        throw new IllegalArgumentException("unsupported mutation " + mutation.kind);
    }

    private static byte[] decodeHex(String value) {
        if (value == null || value.isEmpty() || (value.length() % 2) != 0) {
            throw new IllegalArgumentException("invalid patch hex: " + value);
        }
        byte[] out = new byte[value.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int hi = Character.digit(value.charAt(i * 2), 16);
            int lo = Character.digit(value.charAt(i * 2 + 1), 16);
            if (hi < 0 || lo < 0) throw new IllegalArgumentException("invalid patch hex: " + value);
            out[i] = (byte) ((hi << 4) | lo);
        }
        return out;
    }

    private void applyMutation(Mutation mutation) throws Exception {
        Function function = currentProgram.getFunctionManager().getFunctionContaining(mutation.address);
        if (mutation.kind.equals("rename")) {
            if (function == null) throw new IllegalStateException("no function at " + mutation.address);
            function.setName(mutation.value, SourceType.USER_DEFINED);
        }
        else if (mutation.kind.equals("comment")) {
            int type = mutation.repeatable ? CodeUnit.REPEATABLE_COMMENT : CodeUnit.PRE_COMMENT;
            currentProgram.getListing().setComment(mutation.address, type, mutation.value);
        }
        else if (mutation.kind.equals("type")) {
            if (function == null) throw new IllegalStateException("no function at " + mutation.address);
            FunctionSignatureParser parser = new FunctionSignatureParser(
                currentProgram.getDataTypeManager(), null);
            FunctionDefinitionDataType signature = parser.parse(null, mutation.value);
            ApplyFunctionSignatureCmd command = new ApplyFunctionSignatureCmd(
                function.getEntryPoint(), signature, SourceType.USER_DEFINED);
            if (!command.applyTo(currentProgram, monitor)) throw new IllegalStateException(command.getStatusMsg());
        }
        else if (mutation.kind.equals("patch")) {
            // Byte patching of the in-program image via the flat Memory API.
            // Raw bytes are written directly; stale code units over the patched
            // range are cleared and disassembly is re-attempted so the listing
            // reflects the new bytes. (clearListing(Address, Address) and
            // disassemble(Address) are flat GhidraScript APIs.)
            byte[] payload = decodeHex(mutation.value);
            currentProgram.getMemory().setBytes(mutation.address, payload);
            Address end = mutation.address.add(payload.length - 1);
            clearListing(mutation.address, end);
            disassemble(mutation.address);
        }
        else throw new IllegalArgumentException("unsupported mutation " + mutation.kind);
    }
}
