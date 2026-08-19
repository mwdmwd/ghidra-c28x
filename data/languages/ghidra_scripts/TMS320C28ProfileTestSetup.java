// Create narrowly controlled incompatible initialized ranges for negative tests.
// @category TMS320C28

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

import java.util.LinkedHashMap;
import java.util.Map;

public class TMS320C28ProfileTestSetup extends GhidraScript {
    @Override
    public void run() throws Exception {
        Map<String, String> args = parseArgs(getScriptArgs());
        String mode = args.get("mode");
        if (mode == null) {
            throw new IllegalArgumentException("PROFILE_TEST_SETUP_ERROR: missing mode");
        }
        AddressSpace space = currentProgram.getAddressFactory().getDefaultAddressSpace();
        if (space.getAddressableUnitSize() != 2) {
            throw new IllegalStateException("PROFILE_TEST_SETUP_ERROR: expected two-byte units");
        }
        Memory memory = currentProgram.getMemory();
        if ("accessViewConflict".equals(mode)) {
            setupAccessViewConflict(space, memory);
            println("PROFILE_TEST_SETUP_PASS=" + mode);
            return;
        }
        long word;
        byte[] bytes;
        if ("incompatibleCopyDestination".equals(mode)) {
            word = 0x2040;
            bytes = new byte[] { 1, 2, 3, 4 };
        }
        else if ("incompatibleRom".equals(mode)) {
            word = 0x4010;
            bytes = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0 };
        }
        else {
            throw new IllegalArgumentException("PROFILE_TEST_SETUP_ERROR: unsupported mode=" + mode);
        }

        Address start = space.getAddress(Math.multiplyExact(word, 2L));
        MemoryBlock block = memory.getBlock(start);
        if (block == null) {
            block = memory.createInitializedBlock("FOREIGN_INITIALIZED", start,
                bytes.length, (byte) 0, monitor, false);
        }
        else {
            if (block.getStart().compareTo(start) < 0) {
                memory.split(block, start);
                block = memory.getBlock(start);
            }
            Address endExclusive = start.add(bytes.length);
            if (block.getEnd().compareTo(endExclusive) >= 0) {
                memory.split(block, endExclusive);
                block = memory.getBlock(start);
            }
            if (!block.isInitialized()) {
                block = memory.convertToInitialized(block, (byte) 0);
            }
        }
        block.setSourceName("FOREIGN_TEST_DATA");
        memory.setBytes(start, bytes);
        println("PROFILE_TEST_SETUP_PASS=" + mode);
    }

    private void setupAccessViewConflict(AddressSpace space, Memory memory) throws Exception {
        Address start = space.getAddress(Math.multiplyExact(0x3022L, 2L));
        MemoryBlock block = memory.getBlock(start);
        if (block == null) {
            block = memory.createUninitializedBlock("FOREIGN_ACCESS_VIEW", start, 4L, false);
        }
        else if (block.getStart().compareTo(start) < 0 || block.getEnd().compareTo(start.add(3)) < 0) {
            throw new IllegalStateException(
                "PROFILE_TEST_SETUP_ERROR: incompatible pre-existing access-view block");
        }
        block.setSourceName("FOREIGN_USER_ACCESS_VIEW");
        block.setPermissions(true, true, false);

        Data existing = currentProgram.getListing().getDefinedDataAt(start);
        if (existing == null) {
            existing = currentProgram.getListing().createData(start, ByteDataType.dataType);
        }
        if (existing == null || existing.getLength() != 1) {
            throw new IllegalStateException(
                "PROFILE_TEST_SETUP_ERROR: could not seed one-byte incompatible datum");
        }

        SymbolTable symbols = currentProgram.getSymbolTable();
        Namespace global = currentProgram.getGlobalNamespace();
        Namespace root = symbols.getNamespace("F2837xS_COMPAT", global);
        if (root == null) {
            root = symbols.createNameSpace(global, "F2837xS_COMPAT", SourceType.USER_DEFINED);
        }
        Namespace peripherals = symbols.getNamespace("PERIPHERALS", root);
        if (peripherals == null) {
            peripherals = symbols.createNameSpace(root, "PERIPHERALS", SourceType.USER_DEFINED);
        }
        Namespace cana = symbols.getNamespace("CANA", peripherals);
        if (cana == null) {
            cana = symbols.createNameSpace(peripherals, "CANA", SourceType.USER_DEFINED);
        }
        Symbol label = symbols.getSymbol("IF1ARB_BYTE2", start, cana);
        if (label == null) {
            label = symbols.createLabel(start, "IF1ARB_BYTE2", cana,
                SourceType.USER_DEFINED);
        }
        label.setPrimary();
        label.setPinned(true);
    }

    private static Map<String, String> parseArgs(String[] raw) {
        Map<String, String> result = new LinkedHashMap<>();
        for (String arg : raw) {
            int equals = arg.indexOf('=');
            if (equals <= 0) {
                throw new IllegalArgumentException(
                    "PROFILE_TEST_SETUP_ERROR: expected key=value argument: " + arg);
            }
            result.put(arg.substring(0, equals), arg.substring(equals + 1));
        }
        return result;
    }
}
