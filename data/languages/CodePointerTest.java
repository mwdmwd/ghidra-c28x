// Focused fresh-Ghidra regression for typed executable-target discovery.
//@category TMS320C28

import ghidra.app.plugin.core.analysis.TMS320C28CodePointerAnalyzer;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.SourceType;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class CodePointerTest extends GhidraScript {
    private static final String MARKER =
        TMS320C28CodePointerAnalyzer.MARKER_PROPERTY;

    private static final record Positive(String site, String slot, String target) {
    }

    private static final Positive[] POSITIVES = {
        new Positive("cp_store_standalone_site", "cp_slot_standalone", "cp_runtime_target"),
        new Positive("cp_store_struct_site", "cp_struct_callback", "cp_runtime_target"),
        new Positive("cp_store_initialized_site", "cp_slot_initialized", "cp_runtime_target"),
        new Positive("cp_store_repeat_first_site", "cp_slot_repeat_first", "cp_runtime_target"),
        new Positive("cp_store_repeat_second_site", "cp_slot_repeat_second", "cp_runtime_target"),
        new Positive("cp_store_propagated_site", "cp_slot_propagated", "cp_runtime_target"),
        new Positive("cp_store_existing_site", "cp_slot_existing", "cp_existing_target"),
        new Positive("cp_store_equal_merge_site", "cp_slot_equal_merge", "cp_runtime_target"),
    };

    private static final record Negative(String site, String slot) {
    }

    private static final Negative[] NEGATIVES = {
        new Negative("cp_near_scalar_site", "cp_slot_scalar"),
        new Negative("cp_near_object_pointer_site", "cp_slot_object_pointer"),
        new Negative("cp_near_zero_site", "cp_slot_zero"),
        new Negative("cp_near_all_ones_site", "cp_slot_all_ones"),
        new Negative("cp_near_uninitialized_site", "cp_slot_uninitialized"),
        new Negative("cp_near_nonexec_site", "cp_slot_nonexec"),
        new Negative("cp_near_invalid_site", "cp_slot_invalid"),
        new Negative("cp_near_interior_site", "cp_slot_interior"),
        new Negative("cp_near_partial_store_site", "cp_slot_partial"),
        new Negative("cp_near_dynamic_site", "cp_slot_dynamic"),
        new Negative("cp_near_clobber_site", "cp_slot_clobber"),
        new Negative("cp_near_conflict_site", "cp_slot_conflict"),
        new Negative("cp_near_call_site", "cp_slot_call"),
        new Negative("cp_near_alternate_site", "cp_slot_alternate"),
        new Negative("cp_near_composed_site", "cp_slot_composed"),
    };

    private final Map<String, Address> addresses = new HashMap<>();
    private Listing listing;
    private FunctionManager functions;
    private Memory memory;

    @Override
    public void run() throws Exception {
        require(currentProgram.getAddressFactory().getDefaultAddressSpace()
                .getAddressableUnitSize() == 2,
            "fixture requires two-byte C28x address units");
        parseAddresses();
        listing = currentProgram.getListing();
        functions = currentProgram.getFunctionManager();
        memory = currentProgram.getMemory();

        auditDestinationTypes();
        auditInitialPointerReplacement();
        auditPositiveStores();
        auditNegativeStores();
        auditTargetSafetyRejections();
        auditExistingFunctionReuse();
        auditDistinctCallbackFunctions();

        int functionsBeforeRerun = targetFunctionCount();
        int markersBeforeRerun = markerAddresses().size();
        require(markersBeforeRerun == POSITIVES.length,
            "expected " + POSITIVES.length + " owned markers, got " +
                markersBeforeRerun + ": " + markerAddresses());
        rerunAnalyzer("idempotent-1");
        rerunAnalyzer("idempotent-2");
        require(markerAddresses().size() == markersBeforeRerun,
            "idempotent rerun changed marker count");
        require(targetFunctionCount() == functionsBeforeRerun,
            "idempotent rerun changed accepted target function count");
        auditPositiveStores();
        auditNegativeStores();
        auditExistingFunctionReuse();

        auditMarkerRevocationAndMonotonicFunction();
        auditPositiveStores();
        auditNegativeStores();
        auditExistingFunctionReuse();

        println("CODE_POINTER_ACCEPTED_STORES=" + POSITIVES.length);
        println("CODE_POINTER_REJECTED_STORES=" + NEGATIVES.length);
        println("CODE_POINTER_IDEMPOTENT_RERUNS=2");
        println("CODE_POINTER_MARKER_REVOCATION=1");
        println("CODE_POINTER_WRITE_REFERENCES_PRESERVED=" +
            (POSITIVES.length + NEGATIVES.length));
        println("CODE_POINTER_CALL_EDGES_FABRICATED=0");
        println("CODE_POINTER_TEST_PASS=all");
    }

    private void auditDestinationTypes() {
        for (Positive positive : POSITIVES) {
            require(isExactFunctionPointer(address(positive.slot)),
                positive.slot + " is not an exact function-pointer datum/component");
        }
        require(!isExactFunctionPointer(address("cp_slot_scalar")),
            "scalar destination became a function pointer");
        require(!isExactFunctionPointer(address("cp_slot_object_pointer")),
            "object-pointer destination became a function pointer");

        Data root = listing.getDefinedDataContaining(address("cp_struct_callback"));
        require(root != null && root.isStructure(),
            "structure callback is not contained by defined structure data");
        require(root.getMinAddress().equals(address("cp_struct_root")),
            "structure root address changed");
        require(root.getPrimitiveAt(4) != null &&
                root.getPrimitiveAt(4).getMinAddress().equals(address("cp_struct_callback")),
            "function-pointer component is not exact at offset four");
    }

    private void auditInitialPointerReplacement() throws Exception {
        long initialized = Integer.toUnsignedLong(memory.getInt(address("cp_slot_initialized")));
        require(initialized == wordOffset(address("cp_static_target")),
            "initialized callback value changed: expected 0x" +
                Long.toHexString(wordOffset(address("cp_static_target"))) +
                " got 0x" + Long.toHexString(initialized));
        require(!address("cp_runtime_target").equals(address("cp_static_target")),
            "runtime and static callback entries overlap");
    }

    private void auditPositiveStores() {
        for (Positive positive : POSITIVES) {
            Instruction store = instruction(positive.site);
            requireFullWidthStore(store, positive.site);
            requireOneWrite(store, address(positive.slot), positive.site);
            requireNoCallReference(store, positive.site);
            String expectedMarker = "0x" + Long.toHexString(wordOffset(address(positive.target)));
            require(expectedMarker.equals(store.getStringProperty(MARKER)),
                positive.site + " marker mismatch: expected " + expectedMarker +
                    " got " + store.getStringProperty(MARKER));
            Function target = functions.getFunctionAt(address(positive.target));
            require(target != null,
                positive.site + " did not seed/reuse target " + positive.target);
            requireDataReferenceFromContainingFunction(store, address(positive.target),
                positive.site);
        }
    }

    private void auditNegativeStores() {
        for (Negative negative : NEGATIVES) {
            Instruction store = instruction(negative.site);
            requireOneWrite(store, address(negative.slot), negative.site);
            requireNoCallReference(store, negative.site);
            require(store.getStringProperty(MARKER) == null,
                negative.site + " received unsafe analyzer marker " +
                    store.getStringProperty(MARKER));
        }
        requireStoreWidth(instruction("cp_near_partial_store_site"), 2,
            "partial-width store");
        for (Negative negative : NEGATIVES) {
            if (!negative.site.equals("cp_near_partial_store_site")) {
                requireStoreWidth(instruction(negative.site), 4, negative.site);
            }
        }
    }

    private void auditTargetSafetyRejections() throws Exception {
        require(functions.getFunctionAt(address("cp_scalar_lookalike_target")) == null,
            "scalar-looking code address created a function");
        require(functions.getFunctionAt(address("cp_object_lookalike_target")) == null,
            "object-pointer code address created a function");

        Address uninitialized = toAddr("4000");
        MemoryBlock uninitializedBlock = memory.getBlock(uninitialized);
        require(uninitializedBlock != null && !uninitializedBlock.isInitialized() &&
                uninitializedBlock.isExecute(),
            "uninitialized executable negative block changed");
        require(listing.getInstructionAt(uninitialized) == null &&
                functions.getFunctionAt(uninitialized) == null,
            "uninitialized target was decoded or made a function");

        Address nonexec = address("cp_data_object");
        MemoryBlock nonexecBlock = memory.getBlock(nonexec);
        require(nonexecBlock != null && nonexecBlock.isInitialized() &&
                !nonexecBlock.isExecute(),
            "non-executable target block permissions changed");
        require(functions.getFunctionAt(nonexec) == null,
            "non-executable target became a function");

        Address invalid = address("cp_invalid_target");
        require(listing.getInstructionAt(invalid) == null &&
                functions.getFunctionAt(invalid) == null,
            "invalid-decode target became code/function");

        Address interior = address("cp_interior_target");
        Function containing = functions.getFunctionContaining(interior);
        require(containing != null &&
                containing.getEntryPoint().equals(address("cp_interior_container")),
            "interior target lost containing function");
        require(functions.getFunctionAt(interior) == null,
            "interior target became a competing function entry");

        long allOnes = Integer.toUnsignedLong(memory.getInt(address("cp_all_ones_value")));
        require(allOnes == 0xffff_ffffL,
            "all-ones fixture value changed: 0x" + Long.toHexString(allOnes));
        requireAllOnesConstruction();
    }

    private void auditExistingFunctionReuse() {
        Function existing = functions.getFunctionAt(address("cp_existing_target"));
        require(existing != null, "existing target function disappeared");
        require("user_existing_target".equals(existing.getName()),
            "existing user function was renamed to " + existing.getName());
        require(existing.getSymbol().getSource() == SourceType.USER_DEFINED,
            "existing target lost USER_DEFINED ownership: " +
                existing.getSymbol().getSource());
    }

    private void auditDistinctCallbackFunctions() {
        Function runtime = functions.getFunctionAt(address("cp_runtime_target"));
        Function initialized = functions.getFunctionAt(address("cp_static_target"));
        require(runtime != null && initialized != null,
            "runtime/static callback functions are not both present");
        require(!runtime.getEntryPoint().equals(initialized.getEntryPoint()),
            "runtime/static callback entries collapsed");
        require(!runtime.getBody().contains(initialized.getEntryPoint()) &&
                !initialized.getBody().contains(runtime.getEntryPoint()),
            "runtime/static callback function bodies overlap");
    }

    private void auditMarkerRevocationAndMonotonicFunction() throws Exception {
        Address slot = address("cp_slot_standalone");
        Instruction store = instruction("cp_store_standalone_site");
        Data original = listing.getDefinedDataAt(slot);
        require(original != null && original.getLength() == 4,
            "standalone slot missing before revocation test");
        DataType originalType = original.getDataType();
        Address end = slot.add(3);

        listing.clearCodeUnits(slot, end, false);
        listing.createData(slot, new DWordDataType(currentProgram.getDataTypeManager()));
        rerunAnalyzer("revoke");
        require(store.getStringProperty(MARKER) == null,
            "stale analyzer marker survived destination type change");
        Data userScalar = listing.getDefinedDataAt(slot);
        require(userScalar != null &&
                userScalar.getDataType() instanceof DWordDataType,
            "analyzer overwrote replacement scalar data");
        require(functions.getFunctionAt(address("cp_runtime_target")) != null,
            "monotonic target function was revoked unsafely");
        require(markerAddresses().size() == POSITIVES.length - 1,
            "revocation changed unrelated markers: " + markerAddresses());

        listing.clearCodeUnits(slot, end, false);
        listing.createData(slot, originalType);
        rerunAnalyzer("restore");
        require(store.getStringProperty(MARKER) != null,
            "restored function-pointer destination was not rediscovered");
        require(markerAddresses().size() == POSITIVES.length,
            "marker restore did not return to the accepted set");
    }

    private void rerunAnalyzer(String phase) throws Exception {
        TMS320C28CodePointerAnalyzer analyzer = new TMS320C28CodePointerAnalyzer();
        MessageLog log = new MessageLog();
        boolean result = analyzer.added(currentProgram,
            new AddressSet(currentProgram.getMemory()), monitor, log);
        require(result, "manual analyzer rerun failed during " + phase + ": " + log);
        println("CODE_POINTER_RERUN=" + phase + ":markers=" + markerAddresses().size());
    }

    private int targetFunctionCount() {
        Set<Address> entries = new HashSet<>();
        for (Positive positive : POSITIVES) {
            if (functions.getFunctionAt(address(positive.target)) != null) {
                entries.add(address(positive.target));
            }
        }
        entries.add(address("cp_static_target"));
        int count = 0;
        for (Address entry : entries) {
            if (functions.getFunctionAt(entry) != null) {
                count++;
            }
        }
        return count;
    }

    private Set<Address> markerAddresses() {
        Set<Address> result = new HashSet<>();
        InstructionIterator iterator = listing.getInstructions(true);
        while (iterator.hasNext()) {
            Instruction instruction = iterator.next();
            if (instruction.getStringProperty(MARKER) != null) {
                result.add(instruction.getMinAddress());
            }
        }
        return result;
    }

    private boolean isExactFunctionPointer(Address destination) {
        Data root = listing.getDefinedDataContaining(destination);
        if (root == null) {
            return false;
        }
        long offset = destination.subtract(root.getMinAddress());
        if (offset < 0 || offset > Integer.MAX_VALUE) {
            return false;
        }
        Data primitive = root.getPrimitiveAt((int) offset);
        if (primitive == null ||
                !primitive.getMinAddress().equals(destination) ||
                primitive.getLength() != 4) {
            return false;
        }
        DataType type = unwrap(primitive.getDataType());
        if (!(type instanceof Pointer pointer) || type.getLength() != 4) {
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

    private void requireFullWidthStore(Instruction instruction, String name) {
        requireStoreWidth(instruction, 4, name);
    }

    private void requireStoreWidth(Instruction instruction, int expected, String name) {
        int stores = 0;
        for (PcodeOp op : instruction.getPcode()) {
            if (op.getOpcode() == PcodeOp.STORE) {
                stores++;
                require(op.getNumInputs() == 3,
                    name + " malformed STORE p-code: " + op);
                require(op.getInput(2).getSize() == expected,
                    name + " expected " + expected + "-byte STORE, got " +
                        op.getInput(2).getSize() + ": " + op);
            }
        }
        require(stores == 1, name + " expected one STORE p-code op, got " + stores);
    }

    private void requireOneWrite(Instruction instruction, Address destination,
            String name) {
        int writes = 0;
        for (Reference reference : instruction.getReferencesFrom()) {
            if (reference.isMemoryReference() &&
                    reference.getReferenceType().isWrite()) {
                writes++;
                require(reference.getToAddress().equals(destination),
                    name + " WRITE changed destination: " + reference);
            }
        }
        require(writes == 1, name + " expected one WRITE reference, got " + writes);
    }

    private void requireNoCallReference(Instruction instruction, String name) {
        for (Reference reference : instruction.getReferencesFrom()) {
            require(!reference.getReferenceType().isCall(),
                name + " fabricated CALL reference " + reference);
        }
        require(!instruction.getFlowType().isCall(),
            name + " store flow was reclassified as CALL");
    }

    private void requireDataReferenceFromContainingFunction(Instruction store,
            Address target, String name) {
        Function function = functions.getFunctionContaining(store.getMinAddress());
        require(function != null, name + " has no containing function");
        int dataReferences = 0;
        ReferenceIterator incoming = currentProgram.getReferenceManager()
            .getReferencesTo(target);
        while (incoming.hasNext()) {
            Reference reference = incoming.next();
            if (function.getBody().contains(reference.getFromAddress()) &&
                    reference.getReferenceType().isData() &&
                    !reference.getReferenceType().isCall()) {
                dataReferences++;
            }
        }
        require(dataReferences >= 1,
            name + " lost ordinary DATA reference to " + target);
    }

    private void requireAllOnesConstruction() {
        Function function = functions.getFunctionAt(address("cp_near_all_ones"));
        require(function != null, "all-ones near-miss function missing");
        boolean ah = false;
        boolean al = false;
        boolean copy = false;
        InstructionIterator iterator = listing.getInstructions(function.getBody(), true);
        while (iterator.hasNext()) {
            Instruction instruction = iterator.next();
            String text = instruction.toString().toUpperCase();
            ah |= text.startsWith("MOV AH,") && text.contains("0XFFFF");
            al |= text.startsWith("MOV AL,") && text.contains("0XFFFF");
            copy |= text.equals("MOVL XAR4,ACC") || text.equals("MOVL XAR4, ACC");
        }
        require(ah && al && copy,
            "all-ones near miss lost exact AH/AL construction");
    }

    private Instruction instruction(String name) {
        Instruction instruction = listing.getInstructionAt(address(name));
        require(instruction != null, "missing instruction " + name + " at " + address(name));
        return instruction;
    }

    private long wordOffset(Address address) {
        return address.getOffset() /
            currentProgram.getAddressFactory().getDefaultAddressSpace()
                .getAddressableUnitSize();
    }

    private void parseAddresses() {
        for (String argument : getScriptArgs()) {
            int equals = argument.indexOf('=');
            require(equals > 0 && equals < argument.length() - 1,
                "malformed fixture address " + argument);
            Address address = toAddr(argument.substring(equals + 1));
            require(address != null, "invalid fixture address " + argument);
            addresses.put(argument.substring(0, equals), address);
        }
    }

    private Address address(String name) {
        Address address = addresses.get(name);
        require(address != null, "missing fixture address " + name);
        return address;
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError("CODE_POINTER_TEST_ERROR: " + message);
        }
    }
}
