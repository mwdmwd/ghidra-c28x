// Validate the deterministic synthetic device-profile fixture.
// @category TMS320C28

import ghidra.app.script.GhidraScript;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;

import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

public class TMS320C28ProfileTest extends GhidraScript {
    private AddressSpace space;
    private Memory memory;

    @Override
    public void run() throws Exception {
        Map<String, String> args = parseArgs(getScriptArgs());
        String mode = args.getOrDefault("mode", "positive");

        space = currentProgram.getAddressFactory().getDefaultAddressSpace();
        memory = currentProgram.getMemory();
        require(space.getAddressableUnitSize() == 2,
            "default space must use two-byte addressable units");

        if ("positive".equals(mode)) {
            checkPositive();
        }
        else if ("user-conflict".equals(mode)) {
            checkUserConflict();
        }
        else {
            throw new IllegalArgumentException("PROFILE_TEST_ERROR: unsupported mode=" + mode);
        }
    }

    private void checkPositive() throws Exception {
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

        checkStableSymbols();
        checkOrdinaryTypes();
        checkAccessViews(false);

        Data vector0 = currentProgram.getListing().getDefinedDataAt(wordAddress(0x2080));
        Data vector1 = currentProgram.getListing().getDefinedDataAt(wordAddress(0x2082));
        require(isFunctionPointer(vector0), "first code-vector slot is not a function pointer");
        require(isFunctionPointer(vector1), "second code-vector slot is not a function pointer");

        Function copiedFunction = currentProgram.getFunctionManager().getFunctionAt(wordAddress(0x2040));
        require(copiedFunction != null, "executable copy was not seeded as a function");
        require(currentProgram.getListing().getInstructionAt(wordAddress(0x2040)) != null,
            "executable copy was not disassembled");

        Options profile = currentProgram.getOptions("TMS320C28 Device Profile");
        require("Synthetic-profile-test".equals(profile.getString("Profile Name", "")),
            "profile program options were not recorded");
        require(profile.getInt("Access View Data Created", -1) == 0,
            "second profile pass should reuse both access-view types");
        require(profile.getInt("Access View Data Skipped", -1) == 2,
            "second profile pass did not report two reused access-view types");
        require(profile.getInt("Code Vector Data Created", -1) == 0,
            "second profile pass should reuse both code-vector types");
        require(profile.getInt("Code Vector Data Skipped", -1) == 2,
            "second profile pass did not report two reused code-vector types");
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
        println("PROFILE_TEST_ACCESS_VIEW_TYPES=4,2,2");
        println("PROFILE_TEST_ACCESS_VIEW_SYMBOLS=3");
        println("PROFILE_TEST_ACCESS_VIEW_COMMENTS=2");
        println("PROFILE_TEST_ACCESS_VIEW_IDEMPOTENCE=2");
        println("PROFILE_TEST_CODE_VECTOR_FUNCTION_POINTERS=2");
        println("PROFILE_TEST_PASS=positive");
    }

    private void checkUserConflict() {
        checkOrdinaryTypes();
        checkAccessViews(true);

        Address conflictAddress = wordAddress(0x3022);
        Data conflict = currentProgram.getListing().getDefinedDataAt(conflictAddress);
        require(conflict != null && conflict.getLength() == 1,
            "profile displaced the incompatible user datum");
        Symbol user = findSymbol(conflictAddress,
            "F2837xS_COMPAT::PERIPHERALS::CANA::IF1ARB_BYTE2");
        require(user != null && user.getSource() == SourceType.USER_DEFINED,
            "profile displaced the user-defined access-view symbol");
        require(user.isPrimary(), "user-defined access-view symbol lost primary status");
        require(user.isPinned(), "user-defined access-view symbol lost pinned status");

        Data neighbor = currentProgram.getListing().getDefinedDataAt(wordAddress(0x3023));
        Data following = currentProgram.getListing().getDefinedDataAt(wordAddress(0x3024));
        require(neighbor != null && neighbor.getLength() == 2,
            "unrelated neighboring access view was not typed");
        require(following != null && following.getLength() == 2,
            "following register was rewritten or lost");

        Options profile = currentProgram.getOptions("TMS320C28 Device Profile");
        require(profile.getInt("Access View Data Created", -1) == 0,
            "second conflict pass unexpectedly created access-view data");
        require(profile.getInt("Access View Data Skipped", -1) == 2,
            "second conflict pass did not report deterministic skips");

        println("PROFILE_TEST_USER_VIEW_SYMBOL_PRESERVED=1");
        println("PROFILE_TEST_USER_VIEW_DATA_PRESERVED=1");
        println("PROFILE_TEST_USER_VIEW_NEIGHBOR_APPLIED=1");
        println("PROFILE_TEST_USER_VIEW_IDEMPOTENCE=2");
        println("PROFILE_TEST_PASS=user-conflict");
    }

    private void checkStableSymbols() {
        require(hasSymbol(0x2000, "F2837xS_COMPAT::MEMORY::TEST_RAM_BASE"),
            "missing RAM base symbol");
        require(hasSymbol(0x3000, "F2837xS_COMPAT::BASES::TEST_PERIPH_BASE"),
            "missing peripheral base symbol");
        require(hasSymbol(0x3004, "F2837xS_COMPAT::PERIPHERALS::TESTPERIPH::REG16"),
            "missing 16-bit register symbol");
        require(hasSymbol(0x3006, "F2837xS_COMPAT::PERIPHERALS::TESTPERIPH::REG32"),
            "missing 32-bit register symbol");
        require(hasSymbol(0x3020, "F2837xS_COMPAT::PERIPHERALS::CANA::IF1ARB"),
            "missing logical CAN register symbol");
        require(hasSymbol(0x3022, "F2837xS_COMPAT::PERIPHERALS::CANA::IF1ARB_BYTE2"),
            "missing CAN byte-2 view symbol");
        require(hasSymbol(0x3023, "F2837xS_COMPAT::PERIPHERALS::CANA::IF1ARB_BYTE3"),
            "missing CAN byte-3 view symbol");
        require(hasSymbol(0x3024, "F2837xS_COMPAT::PERIPHERALS::CANA::FOLLOWING16"),
            "missing following register symbol");
        require(hasSymbol(0x2080, "F2837xS_COMPAT::VECTORS::TESTVECT::SYNTH_VECTOR0"),
            "missing first code-vector symbol");
        require(hasSymbol(0x2082, "F2837xS_COMPAT::VECTORS::TESTVECT::SYNTH_VECTOR1"),
            "missing second code-vector symbol");
        require(hasSymbol(0x2040, "F2837xS_COMPAT::RECOVERED::TEST_CODE"),
            "missing recovered-copy symbol");
        require(hasSymbol(0x4010, "F2837xS_COMPAT::ROM_EVIDENCE::RAW_ROM_004010_BASE"),
            "missing raw-ROM evidence symbol");
    }

    private void checkOrdinaryTypes() {
        Data d16 = currentProgram.getListing().getDefinedDataAt(wordAddress(0x3004));
        Data d32 = currentProgram.getListing().getDefinedDataAt(wordAddress(0x3006));
        require(d16 != null && d16.getLength() == 2, "REG16 data type is not two bytes");
        require(d32 != null && d32.getLength() == 4, "REG32 data type is not four bytes");
    }

    private void checkAccessViews(boolean allowConflict) {
        Data logical = currentProgram.getListing().getDefinedDataAt(wordAddress(0x3020));
        Data byte2 = currentProgram.getListing().getDefinedDataAt(wordAddress(0x3022));
        Data byte3 = currentProgram.getListing().getDefinedDataAt(wordAddress(0x3023));
        Data following = currentProgram.getListing().getDefinedDataAt(wordAddress(0x3024));
        require(logical != null && logical.getLength() == 4,
            "logical CAN base register is not a four-byte datum");
        if (!allowConflict) {
            require(byte2 != null && byte2.getLength() == 2,
                "CAN byte-2 view is not a separate two-byte datum");
        }
        require(byte3 != null && byte3.getLength() == 2,
            "CAN byte-3 view is not a separate two-byte datum");
        require(following != null && following.getLength() == 2,
            "following register does not remain non-overlapping");

        require(hasSymbol(0x3020, "F2837xS_COMPAT::PERIPHERALS::CANA::IF1ARB"),
            "missing logical CAN register identity");
        require(hasSymbol(0x3022, "F2837xS_COMPAT::PERIPHERALS::CANA::IF1ARB_BYTE2"),
            "missing byte-2 access-view identity");
        require(hasSymbol(0x3023, "F2837xS_COMPAT::PERIPHERALS::CANA::IF1ARB_BYTE3"),
            "missing byte-3 access-view identity");

        String byte2Comment = currentProgram.getListing().getComment(
            CommentType.PLATE, wordAddress(0x3022));
        String byte3Comment = currentProgram.getListing().getComment(
            CommentType.PLATE, wordAddress(0x3023));
        requireComment(byte2Comment,
            "F2837xS_COMPAT::PERIPHERALS::CANA::IF1ARB_BYTE2", "byte-2 view name");
        requireComment(byte2Comment,
            "parent logical register F2837xS_COMPAT::PERIPHERALS::CANA::IF1ARB",
            "byte-2 parent");
        requireComment(byte2Comment, "logical bits 16-23", "byte-2 logical range");
        requireComment(byte2Comment, "physical C28x word address 0x3022", "byte-2 address");
        requireComment(byte2Comment, "physical storage 16 bits", "byte-2 storage");
        requireComment(byte2Comment, "Message identifier", "byte-2 TI field description");
        requireComment(byte2Comment, "field crosses this byte boundary",
            "byte-2 crossing field");
        requireComment(byte3Comment,
            "F2837xS_COMPAT::PERIPHERALS::CANA::IF1ARB_BYTE3", "byte-3 view name");
        requireComment(byte3Comment, "logical bits 24-31", "byte-3 logical range");
        requireComment(byte3Comment, "physical C28x word address 0x3023", "byte-3 address");
        requireComment(byte3Comment, "Message direction", "byte-3 TI field description");
        requireComment(byte3Comment, "Message valid", "byte-3 upper field description");
    }

    private void requireComment(String comment, String needle, String description) {
        require(comment != null && comment.contains(needle),
            "access-view comment lacks " + description + ": " + comment);
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

    private boolean isFunctionPointer(Data data) {
        if (data == null || data.getLength() != 4) {
            return false;
        }
        DataType type = unwrap(data.getDataType());
        if (!(type instanceof Pointer pointer) || pointer.getLength() != 4) {
            return false;
        }
        return unwrap(pointer.getDataType()) instanceof FunctionDefinition;
    }

    private DataType unwrap(DataType type) {
        Set<DataType> seen = new HashSet<>();
        while (type instanceof TypeDef typedef && seen.add(type)) {
            type = typedef.getBaseDataType();
        }
        return type;
    }

    private boolean hasSymbol(long word, String qualifiedName) {
        return findSymbol(wordAddress(word), qualifiedName) != null;
    }

    private Symbol findSymbol(Address address, String qualifiedName) {
        for (Symbol symbol : currentProgram.getSymbolTable().getSymbols(address)) {
            if (qualifiedName.equals(symbol.getName(true))) {
                return symbol;
            }
        }
        return null;
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
