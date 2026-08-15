// Build exact function-pointer and near-miss destination types before analysis.
//@category TMS320C28

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.Undefined2DataType;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;

import java.util.LinkedHashMap;
import java.util.Map;

/** Pre-analysis setup for the deterministic typed code-pointer fixture. */
public class CodePointerTestSetup extends GhidraScript {
    private static final CategoryPath CATEGORY =
        new CategoryPath("/TMS320C28/CodePointerTest");

    private static final String[] FUNCTION_POINTER_SLOTS = {
        "cp_slot_standalone",
        "cp_slot_initialized",
        "cp_slot_repeat_first",
        "cp_slot_repeat_second",
        "cp_slot_propagated",
        "cp_slot_existing",
        "cp_slot_equal_merge",
        "cp_slot_zero",
        "cp_slot_all_ones",
        "cp_slot_uninitialized",
        "cp_slot_nonexec",
        "cp_slot_invalid",
        "cp_slot_interior",
        "cp_slot_partial",
        "cp_slot_dynamic",
        "cp_slot_clobber",
        "cp_slot_conflict",
        "cp_slot_call",
        "cp_slot_alternate",
        "cp_slot_composed",
    };

    private Map<String, Address> addresses;
    private Listing listing;
    private DataTypeManager dtm;

    @Override
    public void run() throws Exception {
        require(currentProgram.getAddressFactory().getDefaultAddressSpace()
                .getAddressableUnitSize() == 2,
            "fixture requires two-byte C28x address units");
        addresses = parseAddresses();
        listing = currentProgram.getListing();
        dtm = currentProgram.getDataTypeManager();

        FunctionDefinitionDataType signature = new FunctionDefinitionDataType(
            CATEGORY, "cp_callback", dtm);
        signature.setReturnType(new VoidDataType(dtm));
        signature.setArguments();
        DataType resolvedSignature = dtm.addDataType(
            signature, DataTypeConflictHandler.REPLACE_HANDLER);
        DataType functionPointer = new PointerDataType(resolvedSignature, 4, dtm);

        for (String name : FUNCTION_POINTER_SLOTS) {
            applyData(name, functionPointer);
        }

        StructureDataType structure = new StructureDataType(
            CATEGORY, "cp_controller_record", 0, dtm);
        structure.add(new UnsignedShortDataType(dtm), 2, "tag", null);
        structure.add(new Undefined2DataType(dtm), 2, "padding", null);
        structure.add(functionPointer, 4, "callback", null);
        DataType resolvedStructure = dtm.addDataType(
            structure, DataTypeConflictHandler.REPLACE_HANDLER);
        applyData("cp_struct_root", resolvedStructure);
        require(address("cp_struct_callback").equals(
            address("cp_struct_root").add(4)),
            "structure callback symbol lost its byte offset");

        applyData("cp_slot_scalar", new DWordDataType(dtm));
        DataType objectPointer = new PointerDataType(
            new UnsignedShortDataType(dtm), 4, dtm);
        applyData("cp_slot_object_pointer", objectPointer);
        applyData("cp_data_object", new UnsignedShortDataType(dtm));
        applyData("cp_all_ones_value", new DWordDataType(dtm));

        createUninitializedExecutableBlock();
        seedFunction("cp_static_target", "seeded_static_target", SourceType.ANALYSIS);
        seedFunction("cp_existing_target", "user_existing_target", SourceType.USER_DEFINED);
        seedFunction("cp_interior_container", "seeded_interior_container", SourceType.ANALYSIS);

        println("CODE_POINTER_SETUP_FUNCTION_POINTER_SLOTS=" +
            FUNCTION_POINTER_SLOTS.length);
        println("CODE_POINTER_SETUP_STRUCT_COMPONENT=" + address("cp_struct_callback"));
        println("CODE_POINTER_SETUP_PASS=" + currentProgram.getName());
    }

    private void applyData(String name, DataType type) throws Exception {
        Address start = address(name);
        Address end = start.add(type.getLength() - 1L);
        Data existing = listing.getDefinedDataAt(start);
        if (existing != null && existing.getLength() == type.getLength() &&
                existing.getDataType().isEquivalent(type)) {
            return;
        }
        require(listing.isUndefined(start, end),
            name + " is not undefined before fixture typing: " +
                listing.getCodeUnitContaining(start));
        Data created = listing.createData(start, type);
        require(created != null && created.getLength() == type.getLength(),
            "could not apply " + type.getDisplayName() + " at " + name);
    }

    private void createUninitializedExecutableBlock() throws Exception {
        Address start = toAddr("4000");
        require(start != null, "could not resolve uninitialized target address");
        Memory memory = currentProgram.getMemory();
        MemoryBlock block = memory.getBlock(start);
        if (block == null) {
            block = memory.createUninitializedBlock(
                "CP_UNINITIALIZED_EXEC", start, 0x40, false);
        }
        require(!block.isInitialized(), "uninitialized negative block has bytes");
        block.setPermissions(true, false, true);
        block.setVolatile(false);
        println("CODE_POINTER_SETUP_UNINITIALIZED_EXEC=" + start);
    }

    private void seedFunction(String addressName, String functionName,
            SourceType source) throws Exception {
        Address entry = address(addressName);
        if (listing.getInstructionAt(entry) == null) {
            MemoryBlock block = currentProgram.getMemory().getBlock(entry);
            require(block != null && block.isInitialized() && block.isExecute(),
                addressName + " is not initialized executable memory");
            DisassembleCommand command = new DisassembleCommand(
                entry, new AddressSet(block.getStart(), block.getEnd()), true);
            require(command.applyTo(currentProgram, monitor),
                "could not disassemble " + addressName + ": " + command.getStatusMsg());
        }
        Function function = currentProgram.getFunctionManager().getFunctionAt(entry);
        if (function == null) {
            CreateFunctionCmd command = new CreateFunctionCmd(
                functionName, entry, null, source, false, false);
            require(command.applyTo(currentProgram, monitor),
                "could not create " + addressName + ": " + command.getStatusMsg());
            function = currentProgram.getFunctionManager().getFunctionAt(entry);
        }
        require(function != null, "missing seeded function " + addressName);
        if (!functionName.equals(function.getName()) ||
                function.getSymbol().getSource() != source) {
            function.setName(functionName, source);
        }
        require(functionName.equals(function.getName()),
            addressName + " function name mismatch");
        println("CODE_POINTER_SETUP_FUNCTION=" + addressName + ":" + entry +
            ":" + function.getName() + ":" + function.getSymbol().getSource());
    }

    private Map<String, Address> parseAddresses() {
        Map<String, Address> result = new LinkedHashMap<>();
        for (String argument : getScriptArgs()) {
            int equals = argument.indexOf('=');
            require(equals > 0 && equals < argument.length() - 1,
                "malformed fixture address " + argument);
            String name = argument.substring(0, equals);
            Address address = toAddr(argument.substring(equals + 1));
            require(address != null, "invalid fixture address " + argument);
            result.put(name, address);
        }
        return result;
    }

    private Address address(String name) {
        Address address = addresses.get(name);
        require(address != null, "missing fixture address " + name);
        return address;
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError("CODE_POINTER_SETUP_ERROR: " + message);
        }
    }
}
