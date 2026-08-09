// Validate the deterministic synthetic device-profile fixture.
// @category TMS320C28

import ghidra.app.script.GhidraScript;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

public class TMS320C28ProfileTest extends GhidraScript {
    private AddressSpace space;
    private Memory memory;

    @Override
    public void run() throws Exception {
        Map<String, String> args = parseArgs(getScriptArgs());
        String mode = args.getOrDefault("mode", "positive");
        if (!"positive".equals(mode)) {
            throw new IllegalArgumentException("PROFILE_TEST_ERROR: unsupported mode=" + mode);
        }

        space = currentProgram.getAddressFactory().getDefaultAddressSpace();
        memory = currentProgram.getMemory();
        require(space.getAddressableUnitSize() == 2,
            "default space must use two-byte addressable units");

        checkBlock(0x1000, true, true, false, true, false, "firmware flash");
        checkBlock(0x2000, false, true, true, false, false, "ordinary RAM");
        checkBlock(0x3000, false, true, true, false, true, "peripheral window");
        checkBlock(0x4000, false, true, false, true, false, "uninitialized ROM remainder");

        checkBytes(0x2020, words(0x1111, 0x2222, 0x3333), false,
            "positive-length cinit record");
        checkBytes(0x2030, words(0x4444, 0x5555), false,
            "negative-length/32-bit-destination cinit record");
        checkBytes(0x2040, words(0x7700, 0x0006), true,
            "executable explicit copy");
        checkBytes(0x4010, words(0xA55A, 0x1234, 0xBEEF, 0xCAFE), true,
            "raw ROM evidence");

        require(hasSymbol(0x2000, "F2837xS_COMPAT::MEMORY::TEST_RAM_BASE"),
            "missing RAM base symbol");
        require(hasSymbol(0x3000, "F2837xS_COMPAT::BASES::TEST_PERIPH_BASE"),
            "missing peripheral base symbol");
        require(hasSymbol(0x3004, "F2837xS_COMPAT::PERIPHERALS::TESTPERIPH::REG16"),
            "missing 16-bit register symbol");
        require(hasSymbol(0x3006, "F2837xS_COMPAT::PERIPHERALS::TESTPERIPH::REG32"),
            "missing 32-bit register symbol");
        require(hasSymbol(0x2040, "F2837xS_COMPAT::RECOVERED::TEST_CODE"),
            "missing recovered-copy symbol");
        require(hasSymbol(0x4010, "F2837xS_COMPAT::ROM_EVIDENCE::RAW_ROM_004010_BASE"),
            "missing raw-ROM evidence symbol");

        Data d16 = currentProgram.getListing().getDefinedDataAt(wordAddress(0x3004));
        Data d32 = currentProgram.getListing().getDefinedDataAt(wordAddress(0x3006));
        require(d16 != null && d16.getLength() == 2, "REG16 data type is not two bytes");
        require(d32 != null && d32.getLength() == 4, "REG32 data type is not four bytes");

        Function copiedFunction = currentProgram.getFunctionManager().getFunctionAt(wordAddress(0x2040));
        require(copiedFunction != null, "executable copy was not seeded as a function");
        require(currentProgram.getListing().getInstructionAt(wordAddress(0x2040)) != null,
            "executable copy was not disassembled");

        Options profile = currentProgram.getOptions("TMS320C28 Device Profile");
        require("Synthetic-profile-test".equals(profile.getString("Profile Name", "")),
            "profile program options were not recorded");
        Options workspace = currentProgram.getOptions("TMS320C28 Firmware Workspace");
        require("Synthetic-workspace-test".equals(workspace.getString("Workspace Name", "")),
            "firmware workspace program options were not recorded");
        require(workspace.getLong("Recovered Words", -1) == 7,
            "recovered word count must be seven");
        require(workspace.getInt("Explicit Copies", -1) == 1,
            "explicit copy count must be one");
        require(workspace.getInt("Cinit Records", -1) == 2,
            "cinit record count must be two");

        Options rom = currentProgram.getOptions("TMS320C28 ROM Evidence");
        require("synthetic-profile-test-rom".equals(rom.getString("Provenance", "")),
            "ROM provenance was not recorded");
        require(rom.getLong("Word Base", -1) == 0x4010,
            "ROM word base was not recorded");
        require(rom.getLong("Words", -1) == 4,
            "ROM word length was not recorded");

        println("PROFILE_TEST_ADDRESS_UNIT_BYTES=2");
        println("PROFILE_TEST_RECOVERED_WORDS=7");
        println("PROFILE_TEST_REGISTER_WIDTHS=16,32");
        println("PROFILE_TEST_PASS=positive");
    }

    private void checkBlock(long word, boolean initialized, boolean read, boolean write,
            boolean execute, boolean volatileBlock, String description) {
        MemoryBlock block = memory.getBlock(wordAddress(word));
        require(block != null, "missing block for " + description + " at 0x" + Long.toHexString(word));
        require(block.isInitialized() == initialized,
            description + " initialized=" + block.isInitialized() + " expected=" + initialized);
        require(block.isRead() == read, description + " read permission mismatch");
        require(block.isWrite() == write, description + " write permission mismatch");
        require(block.isExecute() == execute, description + " execute permission mismatch");
        require(block.isVolatile() == volatileBlock, description + " volatility mismatch");
    }

    private void checkBytes(long word, byte[] expected, boolean execute, String description)
            throws Exception {
        Address start = wordAddress(word);
        MemoryBlock block = memory.getBlock(start);
        require(block != null && block.isInitialized(), description + " is not initialized");
        require(block.isRead() && block.isWrite() == (word < 0x4000),
            description + " read/write permissions mismatch");
        require(block.isExecute() == execute, description + " execute permission mismatch");
        require(!block.isVolatile(), description + " must not be volatile");
        byte[] actual = new byte[expected.length];
        int count = memory.getBytes(start, actual);
        require(count == expected.length, description + " short read");
        require(Arrays.equals(actual, expected), description + " bytes differ");
        String source = block.getSourceName();
        require(source != null && (source.startsWith("TMS320C28_FIRMWARE_WORKSPACE:") ||
            source.startsWith("TMS320C28_ROM_EVIDENCE:")),
            description + " lacks auditable source provenance");
    }

    private boolean hasSymbol(long word, String qualifiedName) {
        for (Symbol symbol : currentProgram.getSymbolTable().getSymbols(wordAddress(word))) {
            if (qualifiedName.equals(symbol.getName(true))) {
                return true;
            }
        }
        return false;
    }

    private Address wordAddress(long word) {
        return space.getAddress(Math.multiplyExact(word, 2L));
    }

    private static byte[] words(int... values) {
        byte[] out = new byte[values.length * 2];
        for (int i = 0; i < values.length; i++) {
            out[i * 2] = (byte) values[i];
            out[i * 2 + 1] = (byte) (values[i] >>> 8);
        }
        return out;
    }

    private static Map<String, String> parseArgs(String[] raw) {
        Map<String, String> result = new LinkedHashMap<>();
        for (String arg : raw) {
            int equals = arg.indexOf('=');
            if (equals <= 0) {
                throw new IllegalArgumentException(
                    "PROFILE_TEST_ERROR: expected key=value argument: " + arg);
            }
            result.put(arg.substring(0, equals), arg.substring(equals + 1));
        }
        return result;
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new IllegalStateException("PROFILE_TEST_ERROR: " + message);
        }
    }
}
