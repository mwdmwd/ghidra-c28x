// Focused SXM low-half and TI C OVM-return data-flow regression.
//@category TMS320C28

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.plugin.core.analysis.TMS320C28OvmReturnAnalyzer;
import ghidra.app.plugin.core.analysis.TMS320C28ScalarAbiAnalyzer;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

public class StatusModeTest extends GhidraScript {
    private static final String[] LOW_COMBINE = {
        "status_low_combine_store", "status_low_combine_pass"
    };
    private static final String[] LOW_SHIFTS = {
        "status_low_shift_store", "status_low_shift_pass", "status_low_shift15_store"
    };
    private static final String[] FULL_REGISTER = {
        "status_full_unsigned", "status_full_signed", "status_full_signed_shift0",
        "status_full_unsigned_shift15", "status_full_signed_shift15"
    };
    private static final String[] COMPILER_DIRECT_OVM = {
        "status_post_call_sum", "status_post_call_integer",
        "status_unequal_calls", "status_nested_direct"
    };
    private static final String[] VALIDATION_FINAL_OVM = {
        "status_ovm_set_call_add", "status_ovm_clear_add",
        "status_lc_positive", "status_ffc_positive"
    };
    private static final String[] VALIDATION_GENERIC_OVM = {
        "status_ovm_set_add", "status_ovm_conflict_rejoin",
        "status_ovm_ambiguous_call", "status_lc_wrong_model",
        "status_ffc_wrong_model", "status_non_c_entry",
        "status_unproved_entry", "status_stale_function"
    };

    private Listing listing;
    private FunctionManager functions;
    private Register ovmContext;
    private Register sxm;
    private Register ovm;
    private Register ovc;
    private Register v;
    private Register n;
    private Register z;
    private Register acc;
    private Register al;
    private final Map<String, Address> fixtureAddresses = new LinkedHashMap<>();

    @Override
    public void run() throws Exception {
        listing = currentProgram.getListing();
        functions = currentProgram.getFunctionManager();
        ovmContext = currentProgram.getProgramContext().getRegister("ovm_zero");
        sxm = currentProgram.getLanguage().getRegister("SXM");
        ovm = currentProgram.getLanguage().getRegister("OVM");
        ovc = currentProgram.getLanguage().getRegister("OVC");
        v = currentProgram.getLanguage().getRegister("V");
        n = currentProgram.getLanguage().getRegister("N");
        z = currentProgram.getLanguage().getRegister("Z");
        acc = currentProgram.getLanguage().getRegister("ACC");
        al = currentProgram.getLanguage().getRegister("AL");
        require(ovmContext != null && sxm != null && ovm != null && ovc != null &&
            v != null && n != null && z != null && acc != null && al != null,
            "missing status/accumulator registers");

        String kind = parseFixtureArguments();
        if (kind.equals("compiler")) {
            auditCompiler();
            println("STATUS_MODE_PROGRAM_PASS=" + currentProgram.getName());
        }
        else if (kind.equals("validation")) {
            auditValidation();
            println("STATUS_MODE_PROGRAM_PASS=validation");
        }
        else {
            throw new AssertionError("unrecognized status-mode fixture kind " + kind);
        }
    }

    private void auditCompiler() throws Exception {
        auditCompilerSxm();

        Set<Address> expected = new HashSet<>();
        for (String name : COMPILER_DIRECT_OVM) {
            Instruction addu = onlyAddu(function(name));
            require(tagged(addu), name + " did not receive the completed-call OVM=0 fact");
            requireOvmZeroPcode(addu, name);
            expected.add(addu.getMinAddress());
        }

        Instruction known = onlyAddu(function("status_post_known_indirect"));
        Instruction ambiguous = onlyAddu(function("status_post_ambiguous_indirect"));
        require(!tagged(known), "unresolved known-indirect fixture was prematurely proved");
        requireGenericOvmPcode(known, "unresolved known indirect");
        require(!tagged(ambiguous), "ambiguous indirect call was unsafely proved");
        requireGenericOvmPcode(ambiguous, "ambiguous indirect call");

        Instruction call = onlyCall(function("status_post_known_indirect"));
        currentProgram.getReferenceManager().addMemoryReference(
            call.getMinAddress(), address("status_callee"), RefType.COMPUTED_CALL,
            SourceType.USER_DEFINED, 0);
        rerunOvmAnalyzer();
        known = onlyAddu(function("status_post_known_indirect"));
        ambiguous = onlyAddu(function("status_post_ambiguous_indirect"));
        require(tagged(known), "unique referenced indirect C call did not restore OVM=0");
        requireOvmZeroPcode(known, "proved known indirect");
        expected.add(known.getMinAddress());
        require(!tagged(ambiguous), "unreferenced ambiguous indirect call became proved");
        requireGenericOvmPcode(ambiguous, "ambiguous indirect after reanalysis");

        requireContextOnlyOn(expected);
        requireCompletedCallCounts();
        requireCompilerOvmDecompilation();
        println("STATUS_MODE_COMPILER_SXM_LOW_FUNCTIONS=" +
            (LOW_COMBINE.length + LOW_SHIFTS.length + 1));
        println("STATUS_MODE_COMPILER_OVM_CANONICAL_SITES=" + expected.size());
        println("STATUS_MODE_COMPILER_AMBIGUOUS_CALLS_REJECTED=1");
    }

    private void auditCompilerSxm() throws Exception {
        applyConsume16Signature();
        for (String name : LOW_COMBINE) {
            Instruction mov = onlyMovAcc(function(name));
            requireMovMextPcode(mov, name, true);
            String c = decompile(function(name));
            requireLowWidthC(c, name);
            require(c.contains("<< 8") || c.contains("* 0x100") || c.contains("* 256"),
                name + " no longer decompiles as an ordinary byte combine:\n" + c);
        }
        for (String name : LOW_SHIFTS) {
            Instruction mov = onlyMovAcc(function(name));
            requireMovMextPcode(mov, name, true);
            String c = decompile(function(name));
            requireLowWidthC(c, name);
            if (name.contains("15")) {
                require(c.contains("<< 0xf") || c.contains("<< 15") ||
                    c.contains("* 0x8000") || c.contains("* 32768"),
                    name + " lost ordinary shift-15 data flow:\n" + c);
            }
            else {
                require(c.contains("<< 1") || c.contains("* 2"),
                    name + " lost ordinary shift-one data flow:\n" + c);
            }
        }

        Instruction lowVolatile = onlyMovAcc(function("status_low_volatile"));
        requireMovMextPcode(lowVolatile, "status_low_volatile", true);
        requireLowWidthC(decompile(function("status_low_volatile")), "status_low_volatile");

        for (String name : FULL_REGISTER) {
            Instruction mov = onlyMovAcc(function(name));
            requireMovMextPcode(mov, name, false);
            Function function = function(name);
            boolean set = containsMnemonic(function, "SETC");
            boolean clear = containsMnemonic(function, "CLRC");
            if (name.contains("unsigned")) {
                require(clear, name + " lost explicit CLRC SXM");
            }
            else {
                require(set, name + " lost explicit SETC SXM");
            }
        }
        Instruction fullVolatile = onlyMovAcc(function("status_full_volatile"));
        requireMovMextPcode(fullVolatile, "status_full_volatile", true);
        require(containsMnemonic(function("status_full_volatile"), "CLRC"),
            "full volatile fixture lost CLRC SXM");
    }

    private void auditValidation() throws Exception {
        // FFC carries the C boundary contract only after its selected prototype
        // model has actually been established.
        Function ffcTarget = function("status_ffc_target");
        ffcTarget.setCallingConvention("__ffc");
        rerunOvmAnalyzer();

        // A LCR-to-__lc mismatch is deliberately non-C for this call mechanism;
        // rerunning must revoke the initially valid ordinary-LCR tag.
        Function nonC = function("status_non_c_entry");
        nonC.setCallingConvention("__lc");
        rerunOvmAnalyzer();

        Set<Address> expected = new HashSet<>();
        for (String name : VALIDATION_FINAL_OVM) {
            Instruction addu = onlyAddu(function(name));
            require(tagged(addu), name + " was not proved OVM=0");
            requireOvmZeroPcode(addu, name);
            expected.add(addu.getMinAddress());
        }
        for (String name : VALIDATION_GENERIC_OVM) {
            Instruction addu = onlyAddu(function(name));
            require(!tagged(addu), name + " was unsafely proved OVM=0");
            requireGenericOvmPcode(addu, name);
        }
        Instruction alternate = instruction("status_alternate_addu");
        require(isAddu(alternate), "alternate-ingress label no longer identifies ADDU");
        require(!tagged(alternate), "alternate ingress was unsafely proved OVM=0");
        requireGenericOvmPcode(alternate, "status_alternate_ingress");

        require(!tagged(instruction("status_stale_nonaddu")),
            "stale OVM context survived on a non-ADDU instruction");
        requireContextOnlyOn(expected);

        Function setAdd = function("status_ovm_set_add");
        require(containsMnemonic(setAdd, "SETC"), "explicit SETC OVM fixture changed");
        requireGenericOvmPcode(onlyAddu(setAdd), "explicit SETC OVM saturation");

        Instruction unknownSxm = onlyMovAcc(function("status_sxm_unknown_full"));
        requireMovMextPcode(unknownSxm, "status_sxm_unknown_full", false);
        String unknownC = decompile(function("status_sxm_unknown_full"));
        require(unknownC.contains("in_SXM"),
            "full-width unknown-SXM consumer hid architectural SXM:\n" + unknownC);

        println("STATUS_MODE_VALIDATION_OVM_CANONICAL_SITES=" + expected.size());
        println("STATUS_MODE_VALIDATION_OVM_NEAR_MISSES=" +
            (VALIDATION_GENERIC_OVM.length + 1));
        println("STATUS_MODE_VALIDATION_STALE_CONTEXT_REVOKED=2");
        println("STATUS_MODE_VALIDATION_SXM_UNKNOWN_VISIBLE=true");
    }


    private void applyConsume16Signature() throws Exception {
        DataTypeManager dtm = currentProgram.getDataTypeManager();
        DataType u16 = new UnsignedShortDataType(dtm);
        Function function = function("status_consume16");
        List<Variable> parameters = new ArrayList<>();
        parameters.add(new ParameterImpl("value", u16, currentProgram));
        function.updateFunction(Function.DEFAULT_CALLING_CONVENTION_STRING,
            new ReturnParameterImpl(VoidDataType.dataType, currentProgram), parameters,
            FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED);
        boolean custom = TMS320C28ScalarAbiAnalyzer.applyTypedScalarAbi(function);
        require(!custom, "one-u16 fixture unexpectedly required custom scalar storage");
        VariableStorage storage = function.getParameter(0).getVariableStorage();
        require(storage.getVarnodes().length == 1 &&
            isExactRegister(storage.getVarnodes()[0], al),
            "typed 16-bit consumer is not stored in AL: " + storage);
    }

    private void requireCompilerOvmDecompilation() throws Exception {
        for (String name : COMPILER_DIRECT_OVM) {
            String c = decompile(function(name));
            require(!c.contains("in_OVM") && !c.contains("SCARRY") &&
                !c.contains("0x7fffffff"),
                name + " retained an OVM saturation expression:\n" + c);
        }
        String known = decompile(function("status_post_known_indirect"));
        require(!known.contains("in_OVM") && !known.contains("0x7fffffff"),
            "proved known indirect call retained OVM saturation:\n" + known);
    }

    private void requireCompletedCallCounts() throws Exception {
        require(callCount(function("status_post_call_sum")) >= 1,
            "direct-call fixture lost its call");
        require(callCount(function("status_post_call_integer")) >= 1,
            "integer direct-call fixture lost its call");
        require(callCount(function("status_unequal_calls")) >= 2,
            "unequal-call fixture lost its call arms");
        require(hasConditionalFlow(function("status_unequal_calls")),
            "unequal-call fixture lost its branch");
        require(callCount(function("status_nested_direct")) >= 1,
            "nested direct fixture lost its outer call");
    }

    private void requireMovMextPcode(Instruction instruction, String where,
            boolean expectLoad) throws Exception {
        PcodeOp[] ops = instruction.getPcode();
        int loads = 0;
        int accIndex = -1;
        int alIndex = -1;
        PcodeOp accWrite = null;
        PcodeOp alWrite = null;
        for (int index = 0; index < ops.length; index++) {
            PcodeOp op = ops[index];
            if (op.getOpcode() == PcodeOp.LOAD) {
                loads++;
            }
            if (isExactRegister(op.getOutput(), acc)) {
                accIndex = index;
                accWrite = op;
            }
            if (isExactRegister(op.getOutput(), al)) {
                alIndex = index;
                alWrite = op;
            }
        }
        require(loads == (expectLoad ? 1 : 0),
            where + " emitted " + loads + " LOADs, expected " + (expectLoad ? 1 : 0));
        require(accWrite != null && alWrite != null && accIndex < alIndex,
            where + " lacks ordered complete-ACC and explicit-AL writes");
        require(anyInputDependsOn(ops, accWrite, sxm),
            where + " complete result no longer depends on SXM");
        require(!anyInputDependsOn(ops, alWrite, sxm),
            where + " exact low half still depends on SXM");

        PcodeOp nWrite = outputWrite(ops, n);
        PcodeOp zWrite = outputWrite(ops, z);
        require(nWrite != null && zWrite != null,
            where + " no longer writes N/Z");
        require(anyInputDependsOn(ops, nWrite, acc) && anyInputDependsOn(ops, zWrite, acc),
            where + " N/Z are not based on the complete accumulator result");
    }

    private void requireOvmZeroPcode(Instruction instruction, String where) throws Exception {
        requireAdduEncoding(instruction, where);
        PcodeOp[] ops = instruction.getPcode();
        require(!referencesRegister(ops, ovm), where + " still references OVM");
        require(!containsConstant(ops, 0x7fffffffL),
            where + " retained positive-saturation construction");
        require(outputWrite(ops, acc) != null, where + " does not write ACC");
        require(outputWrite(ops, ovc) != null, where + " does not update OVC");
        require(outputWrite(ops, v) != null, where + " does not update sticky V");
        require(outputWrite(ops, n) != null && outputWrite(ops, z) != null,
            where + " does not update N/Z");
    }

    private void requireGenericOvmPcode(Instruction instruction, String where) throws Exception {
        requireAdduEncoding(instruction, where);
        PcodeOp[] ops = instruction.getPcode();
        require(referencesRegister(ops, ovm), where + " lost architectural OVM input");
        require(containsConstant(ops, 0x7fffffffL),
            where + " lost architectural saturation construction");
    }

    private void requireAdduEncoding(Instruction instruction, String where) throws Exception {
        require(instruction.getMnemonicString().equalsIgnoreCase("ADDU"),
            where + " mnemonic changed: " + instruction);
        require(instruction.getNumOperands() == 2 &&
            normalize(instruction.getDefaultOperandRepresentation(0)).equals("ACC"),
            where + " destination changed: " + instruction);
        String source = normalize(instruction.getDefaultOperandRepresentation(1));
        int expectedLow = switch (source) {
            case "AR1" -> 0xa1;
            case "AR6" -> 0xa6;
            default -> -1;
        };
        byte[] bytes = instruction.getBytes();
        require(expectedLow >= 0 && bytes.length == 2 &&
            (bytes[0] & 0xff) == expectedLow && (bytes[1] & 0xff) == 0x0d,
            where + " ADDU bytes/operands changed: " + instruction + " [" + hex(bytes) + "]");
    }

    private void requireLowWidthC(String c, String where) {
        String lower = c.toLowerCase(Locale.ROOT);
        require(!c.contains("in_SXM"), where + " still exposes incoming SXM:\n" + c);
        require(!lower.contains("& -(u") && !lower.contains("& ~-(u") &&
            !lower.contains("0xffff0000") && !lower.contains("0xffffffff"),
            where + " retained mask-selected sign/zero extension:\n" + c);
    }

    private void requireContextOnlyOn(Set<Address> expected) throws Exception {
        Set<Address> actual = new HashSet<>();
        int nonAddu = 0;
        InstructionIterator iterator = listing.getInstructions(true);
        while (iterator.hasNext()) {
            monitor.checkCancelled();
            Instruction instruction = iterator.next();
            if (!tagged(instruction)) {
                continue;
            }
            actual.add(instruction.getMinAddress());
            if (!isAddu(instruction)) {
                nonAddu++;
            }
        }
        require(actual.equals(expected),
            "unexpected OVM context sites: expected=" + expected + " actual=" + actual);
        require(nonAddu == 0, "OVM context leaked onto non-ADDU instructions");
        println("STATUS_MODE_CONTEXT_ON_NON_ADDU=" + nonAddu);
    }

    private void rerunOvmAnalyzer() throws Exception {
        MessageLog log = new MessageLog();
        TMS320C28OvmReturnAnalyzer analyzer = new TMS320C28OvmReturnAnalyzer();
        require(analyzer.added(currentProgram, new AddressSet(currentProgram.getMemory()),
            monitor, log), "OVM analyzer rerun failed: " + log);
        AutoAnalysisManager.getAnalysisManager(currentProgram).startAnalysis(monitor);
        listing = currentProgram.getListing();
        functions = currentProgram.getFunctionManager();
    }

    private String decompile(Function function) throws Exception {
        DecompInterface decompiler = new DecompInterface();
        require(decompiler.openProgram(currentProgram), "failed to open decompiler");
        try {
            DecompileResults results = decompiler.decompileFunction(function, 45, monitor);
            require(results.decompileCompleted() && results.getDecompiledFunction() != null,
                function.getName() + " failed to decompile: " + results.getErrorMessage());
            return results.getDecompiledFunction().getC();
        }
        finally {
            decompiler.dispose();
        }
    }

    private boolean anyInputDependsOn(PcodeOp[] ops, PcodeOp op, Register target) {
        Map<String, PcodeOp> definitions = definitions(ops);
        for (Varnode input : op.getInputs()) {
            if (dependsOnRegister(input, target, definitions, new HashSet<>())) {
                return true;
            }
        }
        return false;
    }

    private boolean dependsOnRegister(Varnode node, Register target,
            Map<String, PcodeOp> definitions, Set<String> active) {
        if (node == null) {
            return false;
        }
        if (overlapsRegister(node, target)) {
            return true;
        }
        String key = varnodeKey(node);
        if (!active.add(key)) {
            return false;
        }
        PcodeOp definition = definitions.get(key);
        if (definition != null) {
            for (Varnode input : definition.getInputs()) {
                if (dependsOnRegister(input, target, definitions, active)) {
                    return true;
                }
            }
        }
        active.remove(key);
        return false;
    }

    private Map<String, PcodeOp> definitions(PcodeOp[] ops) {
        Map<String, PcodeOp> result = new HashMap<>();
        for (PcodeOp op : ops) {
            if (op.getOutput() != null) {
                result.put(varnodeKey(op.getOutput()), op);
            }
        }
        return result;
    }

    private String varnodeKey(Varnode node) {
        return node.getAddress() + ":" + node.getSize();
    }

    private boolean referencesRegister(PcodeOp[] ops, Register target) {
        for (PcodeOp op : ops) {
            if (overlapsRegister(op.getOutput(), target)) {
                return true;
            }
            for (Varnode input : op.getInputs()) {
                if (overlapsRegister(input, target)) {
                    return true;
                }
            }
        }
        return false;
    }

    private boolean containsConstant(PcodeOp[] ops, long value) {
        for (PcodeOp op : ops) {
            for (Varnode input : op.getInputs()) {
                if (input.isConstant() && input.getOffset() == value) {
                    return true;
                }
            }
        }
        return false;
    }

    private PcodeOp outputWrite(PcodeOp[] ops, Register target) {
        for (PcodeOp op : ops) {
            if (isExactRegister(op.getOutput(), target)) {
                return op;
            }
        }
        return null;
    }

    private boolean isExactRegister(Varnode node, Register target) {
        Register register = register(node);
        return register != null && register.equals(target);
    }

    private boolean overlapsRegister(Varnode node, Register target) {
        Register register = register(node);
        return register != null && (register.contains(target) || target.contains(register));
    }

    private Register register(Varnode node) {
        if (node == null || !node.isRegister()) {
            return null;
        }
        return currentProgram.getLanguage().getRegister(node.getAddress(), node.getSize());
    }

    private Instruction onlyMovAcc(Function function) throws Exception {
        List<Instruction> matches = new ArrayList<>();
        InstructionIterator iterator = listing.getInstructions(function.getBody(), true);
        while (iterator.hasNext()) {
            monitor.checkCancelled();
            Instruction instruction = iterator.next();
            if (instruction.getMnemonicString().equalsIgnoreCase("MOV") &&
                instruction.getNumOperands() >= 1 &&
                normalize(instruction.getDefaultOperandRepresentation(0)).equals("ACC")) {
                matches.add(instruction);
            }
        }
        require(matches.size() == 1,
            function.getName() + " contains " + matches.size() + " MOV ACC instructions");
        return matches.get(0);
    }

    private Instruction onlyAddu(Function function) throws Exception {
        List<Instruction> matches = new ArrayList<>();
        InstructionIterator iterator = listing.getInstructions(function.getBody(), true);
        while (iterator.hasNext()) {
            monitor.checkCancelled();
            Instruction instruction = iterator.next();
            if (isAddu(instruction)) {
                matches.add(instruction);
            }
        }
        require(matches.size() == 1,
            function.getName() + " contains " + matches.size() + " ADDU instructions");
        return matches.get(0);
    }

    private Instruction onlyCall(Function function) throws Exception {
        List<Instruction> calls = new ArrayList<>();
        InstructionIterator iterator = listing.getInstructions(function.getBody(), true);
        while (iterator.hasNext()) {
            monitor.checkCancelled();
            Instruction instruction = iterator.next();
            if (instruction.getFlowType().isCall()) {
                calls.add(instruction);
            }
        }
        require(calls.size() == 1,
            function.getName() + " contains " + calls.size() + " calls");
        return calls.get(0);
    }

    private int callCount(Function function) throws Exception {
        int count = 0;
        InstructionIterator iterator = listing.getInstructions(function.getBody(), true);
        while (iterator.hasNext()) {
            monitor.checkCancelled();
            if (iterator.next().getFlowType().isCall()) {
                count++;
            }
        }
        return count;
    }

    private boolean hasConditionalFlow(Function function) throws Exception {
        InstructionIterator iterator = listing.getInstructions(function.getBody(), true);
        while (iterator.hasNext()) {
            monitor.checkCancelled();
            if (iterator.next().getFlowType().isConditional()) {
                return true;
            }
        }
        return false;
    }

    private boolean containsMnemonic(Function function, String mnemonic) throws Exception {
        InstructionIterator iterator = listing.getInstructions(function.getBody(), true);
        while (iterator.hasNext()) {
            monitor.checkCancelled();
            if (iterator.next().getMnemonicString().equalsIgnoreCase(mnemonic)) {
                return true;
            }
        }
        return false;
    }

    private boolean isAddu(Instruction instruction) {
        return instruction != null && instruction.getMnemonicString().equalsIgnoreCase("ADDU") &&
            instruction.getNumOperands() == 2 &&
            normalize(instruction.getDefaultOperandRepresentation(0)).equals("ACC");
    }

    private boolean tagged(Instruction instruction) {
        return instruction != null && BigInteger.ONE.equals(
            currentProgram.getProgramContext().getValue(
                ovmContext, instruction.getMinAddress(), false));
    }

    private Instruction instruction(String name) {
        Instruction instruction = listing.getInstructionAt(address(name));
        require(instruction != null, "missing instruction " + name + " at " + address(name));
        return instruction;
    }

    private Function function(String name) {
        Address address = address(name);
        Function function = functions.getFunctionAt(address);
        require(function != null, "missing function " + name + " at " + address);
        try {
            function.setName(name, SourceType.USER_DEFINED);
        }
        catch (Exception ignored) {
            // Two compiler helper names may intentionally share one folded body.
        }
        return function;
    }

    private String parseFixtureArguments() {
        String[] arguments = getScriptArgs();
        require(arguments.length >= 2, "missing fixture kind/address arguments");
        for (int index = 1; index < arguments.length; index++) {
            String argument = arguments[index];
            int equals = argument.indexOf('=');
            require(equals > 0 && equals < argument.length() - 1,
                "malformed fixture address " + argument);
            Address address = toAddr(argument.substring(equals + 1));
            require(address != null, "invalid fixture address " + argument);
            fixtureAddresses.put(argument.substring(0, equals), address);
        }
        return arguments[0];
    }

    private Address address(String name) {
        Address address = fixtureAddresses.get(name);
        require(address != null, "missing fixture address " + name);
        return address;
    }

    private String normalize(String text) {
        return text == null ? "" : text.replaceAll("\\s+", "").toUpperCase(Locale.ROOT);
    }

    private String hex(byte[] bytes) {
        StringBuilder builder = new StringBuilder();
        for (byte value : bytes) {
            if (builder.length() != 0) builder.append(' ');
            builder.append(String.format("%02x", value & 0xff));
        }
        return builder.toString();
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
