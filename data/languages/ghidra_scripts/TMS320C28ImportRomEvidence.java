// Materialize an explicitly supplied raw C28x ROM image into an already mapped
// device-profile range.  This script never supplies default bytes.
// @category TMS320C28

import ghidra.app.script.GhidraScript;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

import java.io.File;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public class TMS320C28ImportRomEvidence extends GhidraScript {
    private static final String SOURCE_PREFIX = "TMS320C28_ROM_EVIDENCE:";

    @Override
    public void run() throws Exception {
        Map<String, String> args = parseArgs(getScriptArgs());
        String pathArg = require(args, "path");
        String provenance = require(args, "provenance");
        long baseWord = parseLong(require(args, "base"), "base");
        boolean execute = parseBoolean(args.getOrDefault("execute", "true"), "execute");

        AddressSpace space = currentProgram.getAddressFactory().getDefaultAddressSpace();
        int addressUnitBytes = space.getAddressableUnitSize();
        if (addressUnitBytes != 2) {
            fail("expected C28x two-byte addressable units, got " + addressUnitBytes);
        }

        File file = new File(pathArg).getCanonicalFile();
        if (!file.isFile()) {
            fail("ROM evidence file does not exist: " + file);
        }
        byte[] bytes = Files.readAllBytes(file.toPath());
        if (bytes.length == 0 || bytes.length % addressUnitBytes != 0) {
            fail("ROM evidence must contain a positive whole number of C28x words: " + bytes.length);
        }
        long words = bytes.length / addressUnitBytes;
        if (args.containsKey("expectedWords")) {
            long expectedWords = parseLong(args.get("expectedWords"), "expectedWords");
            if (words != expectedWords) {
                fail("ROM evidence length mismatch: expectedWords=" + expectedWords + " actualWords=" + words);
            }
        }
        String actualHash = sha256(bytes);
        String expectedHash = args.get("sha256");
        if (expectedHash != null && !actualHash.equalsIgnoreCase(expectedHash)) {
            fail("ROM evidence SHA-256 mismatch: expected=" + expectedHash + " actual=" + actualHash);
        }

        Address start = wordAddress(space, baseWord);
        Address endExclusive;
        try {
            endExclusive = start.add(bytes.length);
        }
        catch (Exception ex) {
            fail("ROM evidence range overflows the address space: " + ex.getMessage());
            return;
        }
        Memory memory = currentProgram.getMemory();
        preflightMappedAndCompatible(memory, start, endExclusive, bytes);
        List<MemoryBlock> blocks = isolateRange(memory, start, endExclusive);

        int initialized = 0;
        int reused = 0;
        for (MemoryBlock block : blocks) {
            monitor.checkCancelled();
            if (!block.isInitialized()) {
                block = memory.convertToInitialized(block, (byte) 0);
                initialized++;
            }
            else {
                reused++;
            }
            block.setPermissions(true, false, execute);
            block.setVolatile(false);
            block.setSourceName(SOURCE_PREFIX + actualHash + ":" + provenance);
            block.setComment("[TMS320C28 ROM evidence] raw image; provenance: " + provenance +
                "; source file: " + file.getName() + "; SHA-256 " + actualHash);
        }
        memory.setBytes(start, bytes);
        verifyBytes(memory, start, bytes);

        Symbol marker = createMarker(start, baseWord);
        currentProgram.getListing().setComment(start, CommentType.PLATE,
            "[TMS320C28 ROM evidence] " + provenance + "\nSHA-256 " + actualHash +
            "\nRaw C28x bytes loaded from operator-supplied file " + file.getName());

        Options options = currentProgram.getOptions("TMS320C28 ROM Evidence");
        options.setString("Provenance", provenance);
        options.setString("SHA-256", actualHash);
        options.setString("Source File", file.getAbsolutePath());
        options.setLong("Word Base", baseWord);
        options.setLong("Words", words);
        options.setBoolean("Executable", execute);

        println("ROM_EVIDENCE_FILE=" + file);
        println("ROM_EVIDENCE_PROVENANCE=" + provenance);
        println("ROM_EVIDENCE_SHA256=" + actualHash);
        println(String.format(Locale.ROOT, "ROM_EVIDENCE_RANGE=0x%X-0x%X", baseWord, baseWord + words - 1));
        println("ROM_EVIDENCE_BLOCKS_INITIALIZED=" + initialized);
        println("ROM_EVIDENCE_BLOCKS_REUSED=" + reused);
        println("ROM_EVIDENCE_LABEL=" + marker.getName(true));
        println("ROM_EVIDENCE_PASS=" + currentProgram.getName());
    }

    private void preflightMappedAndCompatible(Memory memory, Address start, Address endExclusive,
            byte[] bytes) throws Exception {
        Address cursor = start;
        while (cursor.compareTo(endExclusive) < 0) {
            MemoryBlock block = memory.getBlock(cursor);
            if (block == null) {
                fail("ROM evidence crosses unmapped memory at " + cursor);
            }
            Address segmentEnd = block.getEnd().add(1);
            if (segmentEnd.compareTo(endExclusive) > 0) {
                segmentEnd = endExclusive;
            }
            int offset = Math.toIntExact(cursor.subtract(start));
            int length = Math.toIntExact(segmentEnd.subtract(cursor));
            if (block.isInitialized()) {
                byte[] existing = new byte[length];
                int count = memory.getBytes(cursor, existing);
                if (count != length) {
                    fail("short read while checking initialized ROM overlap at " + cursor);
                }
                for (int i = 0; i < length; i++) {
                    if (existing[i] != bytes[offset + i]) {
                        fail("incompatible initialized ROM overlap at " + cursor.add(i) +
                            ": existing=0x" + Integer.toHexString(existing[i] & 0xff) +
                            " supplied=0x" + Integer.toHexString(bytes[offset + i] & 0xff));
                    }
                }
            }
            cursor = segmentEnd;
        }
    }

    private List<MemoryBlock> isolateRange(Memory memory, Address start, Address endExclusive)
            throws Exception {
        List<MemoryBlock> result = new ArrayList<>();
        Address cursor = start;
        while (cursor.compareTo(endExclusive) < 0) {
            MemoryBlock block = memory.getBlock(cursor);
            if (block == null) {
                fail("ROM evidence crosses unmapped memory at " + cursor);
            }
            if (block.getStart().compareTo(cursor) < 0) {
                memory.split(block, cursor);
                block = memory.getBlock(cursor);
            }
            if (block.getEnd().compareTo(endExclusive) >= 0 &&
                    block.getStart().compareTo(endExclusive) < 0) {
                memory.split(block, endExclusive);
                block = memory.getBlock(cursor);
            }
            result.add(block);
            cursor = block.getEnd().add(1);
        }
        return result;
    }

    private void verifyBytes(Memory memory, Address start, byte[] expected) throws Exception {
        byte[] actual = new byte[expected.length];
        int count = memory.getBytes(start, actual);
        if (count != expected.length) {
            fail("short read after loading ROM evidence: " + count + "/" + expected.length);
        }
        for (int i = 0; i < expected.length; i++) {
            if (actual[i] != expected[i]) {
                fail("ROM evidence verification mismatch at " + start.add(i));
            }
        }
    }

    private Symbol createMarker(Address start, long baseWord) throws Exception {
        SymbolTable symbols = currentProgram.getSymbolTable();
        Namespace root = symbols.getOrCreateNameSpace(currentProgram.getGlobalNamespace(),
            "F2837xS_COMPAT", SourceType.ANALYSIS);
        Namespace evidence = symbols.getOrCreateNameSpace(root, "ROM_EVIDENCE", SourceType.ANALYSIS);
        String name = String.format(Locale.ROOT, "RAW_ROM_%06X_BASE", baseWord);
        Symbol marker = null;
        for (Symbol symbol : symbols.getSymbols(name, evidence)) {
            if (!symbol.getAddress().equals(start)) {
                fail("ROM evidence symbol collision: " + name);
            }
            marker = symbol;
        }
        if (marker == null) {
            marker = symbols.createLabel(start, name, evidence, SourceType.ANALYSIS);
        }
        Symbol primary = symbols.getPrimarySymbol(start);
        if (!marker.isPrimary() &&
                (primary == null || primary.isDynamic() || primary.getSource() == SourceType.ANALYSIS)) {
            marker.setPrimary();
        }
        return marker;
    }

    private Address wordAddress(AddressSpace space, long word) {
        if (word < 0 || word > Long.MAX_VALUE / 2) {
            fail("invalid word address: " + word);
        }
        return space.getAddress(word * 2);
    }

    private static String sha256(byte[] bytes) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        StringBuilder out = new StringBuilder();
        for (byte b : digest.digest(bytes)) {
            out.append(String.format(Locale.ROOT, "%02x", b & 0xff));
        }
        return out.toString();
    }

    private static Map<String, String> parseArgs(String[] raw) {
        Map<String, String> result = new LinkedHashMap<>();
        for (String arg : raw) {
            int equals = arg.indexOf('=');
            if (equals <= 0) {
                throw new IllegalArgumentException("ROM_EVIDENCE_ERROR: expected key=value argument: " + arg);
            }
            result.put(arg.substring(0, equals), arg.substring(equals + 1));
        }
        return result;
    }

    private static String require(Map<String, String> args, String key) {
        String value = args.get(key);
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("ROM_EVIDENCE_ERROR: missing required argument " + key);
        }
        return value;
    }

    private static long parseLong(String value, String name) {
        try {
            return Long.decode(value);
        }
        catch (NumberFormatException ex) {
            throw new IllegalArgumentException("ROM_EVIDENCE_ERROR: invalid " + name + "=" + value, ex);
        }
    }

    private static boolean parseBoolean(String value, String name) {
        if (value.equalsIgnoreCase("true") || value.equals("1") || value.equalsIgnoreCase("yes")) {
            return true;
        }
        if (value.equalsIgnoreCase("false") || value.equals("0") || value.equalsIgnoreCase("no")) {
            return false;
        }
        throw new IllegalArgumentException("ROM_EVIDENCE_ERROR: invalid boolean " + name + "=" + value);
    }

    private void fail(String message) {
        throw new IllegalStateException("ROM_EVIDENCE_ERROR: " + message);
    }
}
