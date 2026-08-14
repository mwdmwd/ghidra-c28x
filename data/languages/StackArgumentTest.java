// Focused outgoing-vs-incoming stack argument and completed-call regression.
//@category TMS320C28

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.plugin.core.analysis.TMS320C28CallConventionAnalyzer;
import ghidra.app.plugin.core.analysis.TMS320C28FfcReturnAnalyzer;
import ghidra.app.plugin.core.analysis.TMS320C28ScalarAbiAnalyzer;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FloatDataType;
import ghidra.program.model.data.LongDataType;
import ghidra.program.model.data.LongLongDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.ShortDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.SourceType;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public class StackArgumentTest extends GhidraScript {
    private static final String[] NO_ARGUMENT_FUNCTIONS = {
        "stack_noarg_lcr", "stack_noarg_ffc", "stack_reuse_ffc",
        "stack_noarg_div", "stack_mixed_caller", "stack_escape_local",
        "stack_conditional_noarg", "stack_leaf_noarg", "stack_nonleaf_noarg"
    };

    private static final String[] RAW_CALLERS = {
        "stack_noarg_lcr", "stack_noarg_ffc", "stack_reuse_ffc",
        "stack_noarg_div", "stack_incoming_live", "stack_mixed_caller",
        "stack_escape_local", "stack_conditional_noarg", "stack_nonleaf_noarg"
    };

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }

    @Override
    public void run() throws Exception {
        String lower = currentProgram.getName().toLowerCase(Locale.ROOT);
        String optimization = lower.contains("_o2") ? "O2" :
            lower.contains("_o0") ? "O0" : "UNKNOWN";
        require(!"UNKNOWN".equals(optimization),
            "unknown stack-argument fixture " + currentProgram.getName());

        rerunCallMechanismAnalyzers();
        testCompilerSpec();
        testFfcProof();
        testInstructionFrames(optimization);
        testCompletedCallPcode();
        testUntypedRecovery(optimization);
        testTypedStorageAndAliases(optimization);

        println("STACK_ARGUMENT_OPTIMIZATION=" + optimization);
        println("STACK_ARGUMENT_PROGRAM_PASS=" + currentProgram.getName());
    }

    private Function function(String name) {
        List<Function> found = getGlobalFunctions(name);
        require(found.size() == 1,
            "expected one function " + name + ", got " + found.size());
        return found.get(0);
    }

    private List<Instruction> instructions(Function function) {
        ArrayList<Instruction> result = new ArrayList<>();
        InstructionIterator iterator = currentProgram.getListing().getInstructions(
            function.getBody(), true);
        while (iterator.hasNext()) {
            result.add(iterator.next());
        }
        return result;
    }

    private DecompileResults decompile(Function function, String style) {
        DecompInterface decompiler = new DecompInterface();
        require(decompiler.setSimplificationStyle(style),
            "unsupported simplification style " + style);
        require(decompiler.openProgram(currentProgram), "failed to open decompiler");
        try {
            DecompileResults results = decompiler.decompileFunction(function, 45, monitor);
            require(results.decompileCompleted(),
                style + " failed for " + function.getName() + ": " +
                    results.getErrorMessage());
            require(results.getHighFunction() != null,
                "missing HighFunction for " + function.getName());
            if ("decompile".equals(style)) {
                require(results.getDecompiledFunction() != null,
                    "missing C for " + function.getName());
            }
            return results;
        }
        finally {
            decompiler.dispose();
        }
    }

    private void rerunCallMechanismAnalyzers() throws Exception {
        AddressSet all = new AddressSet(currentProgram.getMemory());
        MessageLog log = new MessageLog();
        TMS320C28FfcReturnAnalyzer ffc = new TMS320C28FfcReturnAnalyzer();
        require(ffc.added(currentProgram, all, monitor, log),
            "FFC analyzer rerun failed: " + log);
        AutoAnalysisManager.getAnalysisManager(currentProgram).startAnalysis(monitor);

        TMS320C28CallConventionAnalyzer convention =
            new TMS320C28CallConventionAnalyzer();
        require(convention.added(currentProgram, all, monitor, log),
            "call-mechanism analyzer rerun failed: " + log);
        AutoAnalysisManager.getAnalysisManager(currentProgram).startAnalysis(monitor);
        println("STACK_ARGUMENT_CALL_MECHANISM_RERUN=PASS");
    }

    private Register register(Varnode node) {
        if (node == null || !node.isRegister()) {
            return null;
        }
        return currentProgram.getLanguage().getRegister(node.getAddress(), node.getSize());
    }

    private boolean isRegister(Varnode node, String name) {
        Register found = register(node);
        return found != null && name.equals(found.getName());
    }

    private boolean outputRegister(PcodeOp op, String name) {
        return isRegister(op.getOutput(), name);
    }

    private boolean constant(Varnode node, long value) {
        return node != null && node.isConstant() && node.getOffset() == value;
    }

    private boolean binaryRegisterConstant(PcodeOp op, int opcode, String register,
            long value) {
        if (op.getOpcode() != opcode || !outputRegister(op, register) ||
            op.getNumInputs() != 2) {
            return false;
        }
        return (isRegister(op.getInput(0), register) && constant(op.getInput(1), value)) ||
            (isRegister(op.getInput(1), register) && constant(op.getInput(0), value));
    }

    private void requireStack(VariableStorage storage, int offset, int size,
            String context) {
        require(storage.hasStackStorage() && storage.getStackOffset() == offset &&
            storage.size() == size,
            context + " expected Stack[" + offset + "]:" + size + ", got " + storage);
    }

    private void requireRegisters(VariableStorage storage, String... expected) {
        Varnode[] nodes = storage.getVarnodes();
        require(nodes.length == expected.length,
            "expected " + expected.length + " storage pieces, got " + storage);
        for (int index = 0; index < expected.length; index++) {
            require(isRegister(nodes[index], expected[index]),
                "expected storage piece " + expected[index] + ", got " + storage);
        }
    }

    private void requireSyntheticStack(PrototypeModel model, DataType tail,
            int offset, int size, String context) {
        DataTypeManager dtm = currentProgram.getDataTypeManager();
        DataType pointer = new PointerDataType(new ShortDataType(dtm), dtm);
        DataType floating = new FloatDataType(dtm);
        DataType integer32 = new LongDataType(dtm);
        DataType[] types = {
            VoidDataType.dataType,
            pointer, pointer,
            floating, floating, floating, floating,
            integer32,
            tail
        };
        VariableStorage[] storage = model.getStorageLocations(currentProgram, types, false);
        require(storage.length == types.length,
            context + " storage count mismatch: " + storage.length);
        requireStack(storage[storage.length - 1], offset, size, context);
    }

    private void testCompilerSpec() {
        CompilerSpec spec = currentProgram.getCompilerSpec();
        Register sp = spec.getStackPointer();
        require(sp != null && "SP".equals(sp.getName()) &&
            sp.getMinimumByteSize() == 4, "stack pointer must be SP:4");
        require(!spec.stackGrowsNegative(), "C28x stack must grow positive");
        require(spec.getStackSpace().getAddressableUnitSize() == 2,
            "C28x stack addressable unit must be one 16-bit word");

        PrototypeModel standard = spec.getDefaultCallingConvention();
        PrototypeModel lc = currentProgram.getFunctionManager().getCallingConvention("__lc");
        PrototypeModel ffc = currentProgram.getFunctionManager().getCallingConvention("__ffc");
        require(standard != null && lc != null && ffc != null,
            "missing standard, LC, or FFC compiler prototype");
        require(standard.getStackshift() == 0 && lc.getStackshift() == 0 &&
            ffc.getStackshift() == 0,
            "completed ordinary calls must have zero net model SP movement");
        require(Long.valueOf(-4).equals(standard.getStackParameterOffset()),
            "standard reverse stack boundary changed: " +
                standard.getStackParameterOffset());
        require(Long.valueOf(-4).equals(lc.getStackParameterOffset()),
            "LC reverse stack boundary changed: " + lc.getStackParameterOffset());
        require(Long.valueOf(0).equals(ffc.getStackParameterOffset()),
            "FFC reverse stack boundary must be entry SP: " +
                ffc.getStackParameterOffset());

        Varnode[] standardRa = standard.getReturnAddress();
        Varnode[] lcRa = lc.getReturnAddress();
        Varnode[] ffcRa = ffc.getReturnAddress();
        require(standardRa.length == 1 && isRegister(standardRa[0], "RPC"),
            "LCR model must use RPC return state");
        require(lcRa.length == 0, "LC model must not invent RPC state");
        require(ffcRa.length == 1 && isRegister(ffcRa[0], "XAR7"),
            "FFC model must use XAR7 return state");

        DataTypeManager dtm = currentProgram.getDataTypeManager();
        DataType s16 = new ShortDataType(dtm);
        DataType s32 = new LongDataType(dtm);
        DataType s64 = new LongLongDataType(dtm);
        for (PrototypeModel model : new PrototypeModel[] { standard, lc }) {
            String name = model == standard ? "standard" : "LC";
            requireSyntheticStack(model, s16, -6, 2, name + " first exhausted 16-bit");
            requireSyntheticStack(model, s32, -8, 4, name + " first exhausted 32-bit");
            requireSyntheticStack(model, s64, -12, 8, name + " first exhausted 64-bit");
        }
        requireSyntheticStack(ffc, s16, -2, 2, "FFC first exhausted 16-bit");
        requireSyntheticStack(ffc, s32, -4, 4, "FFC first exhausted 32-bit");
        requireSyntheticStack(ffc, s64, -8, 8, "FFC first exhausted 64-bit");

        println("STACK_ARGUMENT_STACK_GROWTH=POSITIVE");
        println("STACK_ARGUMENT_STACK_UNIT_BYTES=2");
        println("STACK_ARGUMENT_MODEL_BOUNDARIES=PASS");
        println("STACK_ARGUMENT_MODEL_16_32_64_OFFSETS=PASS");
    }

    private int pcodeCount(Instruction instruction, int opcode) {
        int count = 0;
        for (PcodeOp op : instruction.getPcode()) {
            if (op.getOpcode() == opcode) {
                count++;
            }
        }
        return count;
    }

    private Instruction terminalLb(Function helper) {
        Instruction result = null;
        for (Instruction instruction : instructions(helper)) {
            if ("LB".equalsIgnoreCase(instruction.getMnemonicString())) {
                result = instruction;
            }
        }
        require(result != null, "missing terminal LB in " + helper.getName());
        return result;
    }

    private int directFfcCallers(Address target) {
        int count = 0;
        InstructionIterator iterator = currentProgram.getListing().getInstructions(true);
        while (iterator.hasNext()) {
            Instruction instruction = iterator.next();
            if (!"FFC".equalsIgnoreCase(instruction.getMnemonicString())) {
                continue;
            }
            for (Address flow : instruction.getFlows()) {
                if (target.equals(flow)) {
                    count++;
                }
            }
        }
        return count;
    }

    private void testFfcProof() {
        Register context = currentProgram.getProgramContext().getRegister("ffc_return");
        require(context != null, "missing ffc_return context register");

        Function helper = function("stack_ffc_helper");
        Function division = function("__c28xabi_divl");
        require("__ffc".equals(helper.getCallingConventionName()),
            "stack_ffc_helper did not select __ffc");
        require("__ffc".equals(division.getCallingConventionName()),
            "__c28xabi_divl did not select __ffc");
        require(directFfcCallers(helper.getEntryPoint()) == 3,
            "stack_ffc_helper must have three exclusive FFC callers");
        require(directFfcCallers(division.getEntryPoint()) == 1,
            "__c28xabi_divl must have one exclusive FFC caller");

        for (Function function : new Function[] { helper, division }) {
            Instruction terminal = terminalLb(function);
            BigInteger tagged = currentProgram.getProgramContext().getValue(context,
                terminal.getMinAddress(), false);
            require(BigInteger.ONE.equals(tagged),
                function.getName() + " terminal was not FFC-tagged");
            require(terminal.getFlowType().isTerminal() &&
                pcodeCount(terminal, PcodeOp.RETURN) == 1 &&
                pcodeCount(terminal, PcodeOp.BRANCHIND) == 0 &&
                pcodeCount(terminal, PcodeOp.CALLIND) == 0,
                function.getName() + " terminal LB did not become RETURNIND");
        }
        println("STACK_ARGUMENT_FFC_HELPERS=2");
        println("STACK_ARGUMENT_FFC_CALLERS=4");
        println("STACK_ARGUMENT_FFC_RETURN_PROOF=PASS");
    }

    private String compact(Instruction instruction) {
        return instruction.toString().replaceAll("\\s+", "").toUpperCase(Locale.ROOT);
    }

    private int countMnemonic(String functionName, String mnemonic) {
        int count = 0;
        for (Instruction instruction : instructions(function(functionName))) {
            if (mnemonic.equalsIgnoreCase(instruction.getMnemonicString())) {
                count++;
            }
        }
        return count;
    }

    private boolean hasText(String functionName, String needle) {
        String desired = needle.replaceAll("\\s+", "").toUpperCase(Locale.ROOT);
        for (Instruction instruction : instructions(function(functionName))) {
            if (compact(instruction).contains(desired)) {
                return true;
            }
        }
        return false;
    }

    private void requireText(String functionName, String needle) {
        require(hasText(functionName, needle),
            functionName + " lacks instruction evidence " + needle);
    }

    private Long scalarOperand(Instruction instruction, int operand) {
        Scalar scalar = instruction.getScalar(operand);
        return scalar == null ? null : scalar.getUnsignedValue();
    }

    private boolean hasMnemonicImmediate(String functionName, String mnemonic, long value) {
        for (Instruction instruction : instructions(function(functionName))) {
            if (!mnemonic.equalsIgnoreCase(instruction.getMnemonicString())) {
                continue;
            }
            for (int operand = 0; operand < instruction.getNumOperands(); operand++) {
                Long scalar = scalarOperand(instruction, operand);
                if (scalar != null && scalar.longValue() == value) {
                    return true;
                }
            }
        }
        return false;
    }

    private void requireFrame(String functionName, int... allowedWords) {
        Integer add = null;
        Integer sub = null;
        for (Instruction instruction : instructions(function(functionName))) {
            String mnemonic = instruction.getMnemonicString();
            if (!"ADDB".equalsIgnoreCase(mnemonic) &&
                !"SUBB".equalsIgnoreCase(mnemonic)) {
                continue;
            }
            for (int operand = 0; operand < instruction.getNumOperands(); operand++) {
                Long scalar = scalarOperand(instruction, operand);
                if (scalar == null) {
                    continue;
                }
                for (int words : allowedWords) {
                    if (scalar.longValue() == words) {
                        if ("ADDB".equalsIgnoreCase(mnemonic)) {
                            add = words;
                        }
                        else {
                            sub = words;
                        }
                    }
                }
            }
        }
        require(add != null && add.equals(sub),
            functionName + " frame allocation/deallocation mismatch: add=" + add +
                " sub=" + sub);
    }

    private void testInstructionFrames(String optimization) {
        requireFrame("stack_noarg_lcr", 4);
        require(countMnemonic("stack_noarg_lcr", "LCR") == 1,
            "stack_noarg_lcr must contain one LCR");

        requireFrame("stack_noarg_ffc", 4);
        require(countMnemonic("stack_noarg_ffc", "FFC") == 1,
            "stack_noarg_ffc must contain one FFC");

        requireFrame("stack_reuse_ffc", 2);
        require(countMnemonic("stack_reuse_ffc", "FFC") == 2,
            "stack_reuse_ffc must contain two FFC calls");
        requireFrame("stack_noarg_div", 2);
        require(countMnemonic("stack_noarg_div", "FFC") == 1,
            "stack_noarg_div must contain one FFC");

        requireFrame("stack_incoming_live", 2, 4);
        require(countMnemonic("stack_incoming_live", "LCR") == 1,
            "stack_incoming_live must contain one nested LCR");

        requireFrame("stack_mixed_caller", 8);
        require(countMnemonic("stack_mixed_caller", "LCR") == 1,
            "stack_mixed_caller must contain one LCR");

        requireFrame("stack_escape_local", 2);
        require(hasMnemonicImmediate("stack_escape_local", "SUBB", 2),
            "stack_escape_local lost XAR4 frame-address subtraction");
        require(countMnemonic("stack_escape_local", "LCR") == 1,
            "stack_escape_local must call its aliasing helper");

        require(hasMnemonicImmediate("stack_conditional_noarg", "ADDB", 4),
            "conditional fixture lost its four-word frame allocation");
        require(countMnemonic("stack_conditional_noarg", "LCR") == 1,
            "conditional fixture must have one call path");
        require(countMnemonic("stack_conditional_noarg", "B") +
                countMnemonic("stack_conditional_noarg", "SB") >= 1,
            "conditional fixture lost its branch/rejoin");

        require(countMnemonic("stack_leaf_noarg", "ADDB") == 0 &&
                countMnemonic("stack_leaf_noarg", "LCR") == 0,
            "leaf control unexpectedly gained a frame or call");
        requireFrame("stack_nonleaf_noarg", 2);
        require(countMnemonic("stack_nonleaf_noarg", "LCR") == 2,
            "non-leaf control must contain two calls");

        require(hasMnemonicImmediate("__c28xabi_divl", "RPT", 31),
            "__c28xabi_divl lost RPT #31");

        println("STACK_ARGUMENT_FRAME_EVIDENCE_" + optimization + "=PASS");
        println("STACK_ARGUMENT_LOCAL_OUTGOING_SEPARATION=PASS");
        println("STACK_ARGUMENT_CONDITIONAL_REJOIN=PASS");
        println("STACK_ARGUMENT_LEAF_CONTROLS=PASS");
    }

    private List<PcodeOpAST> highOps(DecompileResults results) {
        ArrayList<PcodeOpAST> result = new ArrayList<>();
        Iterator<PcodeOpAST> iterator = results.getHighFunction().getPcodeOps();
        while (iterator.hasNext()) {
            result.add(iterator.next());
        }
        return result;
    }

    private void requireRawFfcState(String functionName, Instruction instruction) {
        PcodeOp[] ops = instruction.getPcode();
        int calls = 0;
        int spAdds = 0;
        int spSubs = 0;
        int rpcStores = 0;
        int rpcLoads = 0;
        int xar7Copies = 0;
        int callIndex = -1;
        int xar7CopyIndex = -1;
        for (int index = 0; index < ops.length; index++) {
            PcodeOp op = ops[index];
            if (op.getOpcode() == PcodeOp.CALL ||
                op.getOpcode() == PcodeOp.CALLIND) {
                calls++;
                callIndex = index;
            }
            if (binaryRegisterConstant(op, PcodeOp.INT_ADD, "SP", 2)) {
                spAdds++;
            }
            if (binaryRegisterConstant(op, PcodeOp.INT_SUB, "SP", 2)) {
                spSubs++;
            }
            if (op.getOpcode() == PcodeOp.STORE && op.getNumInputs() == 3 &&
                isRegister(op.getInput(1), "SP") &&
                isRegister(op.getInput(2), "RPC")) {
                rpcStores++;
            }
            if (op.getOpcode() == PcodeOp.LOAD && outputRegister(op, "RPC") &&
                op.getNumInputs() == 2 && isRegister(op.getInput(1), "SP")) {
                rpcLoads++;
            }
            if (op.getOpcode() == PcodeOp.COPY && outputRegister(op, "XAR7")) {
                xar7Copies++;
                xar7CopyIndex = index;
            }
        }
        require(calls == 1 && spAdds == 0 && spSubs == 0 &&
                rpcStores == 0 && rpcLoads == 0 && xar7Copies == 1,
            functionName + " raw FFC at " + instruction.getAddress() +
                " gained RPC/SP state or lost XAR7 setup: calls=" + calls +
                " adds=" + spAdds + " subs=" + spSubs +
                " stores=" + rpcStores + " loads=" + rpcLoads +
                " XAR7 copies=" + xar7Copies);
        require(xar7CopyIndex >= 0 && callIndex >= 0 && xar7CopyIndex < callIndex,
            functionName + " raw FFC return-address setup is not before CALL");
    }

    private int completedCalls(String functionName, String mnemonic) {
        DecompileResults first = decompile(function(functionName), "firstpass");
        List<PcodeOpAST> ops = highOps(first);
        int calls = 0;
        for (int index = 0; index < ops.size(); index++) {
            PcodeOpAST call = ops.get(index);
            if (call.getOpcode() != PcodeOp.CALL &&
                call.getOpcode() != PcodeOp.CALLIND) {
                continue;
            }
            Instruction instruction = currentProgram.getListing().getInstructionContaining(
                call.getSeqnum().getTarget());
            if (instruction == null ||
                !mnemonic.equalsIgnoreCase(instruction.getMnemonicString())) {
                continue;
            }
            calls++;
            if ("FFC".equalsIgnoreCase(mnemonic)) {
                /*
                 * First-pass High P-Code is allowed to schedule caller epilogue
                 * operations at the call sequence point.  The architectural
                 * completed-call state is therefore checked on the FFC
                 * instruction's structural P-Code itself: XAR7 is set once,
                 * before CALL, and no RPC/SP call-save state is present.
                 */
                requireRawFfcState(functionName, instruction);
                continue;
            }
            int spAdds = 0;
            int spSubs = 0;
            int rpcStores = 0;
            int rpcLoads = 0;
            int xar7Copies = 0;
            int callIndexAtAddress = -1;
            int xar7CopyIndex = -1;
            for (int candidateIndex = 0; candidateIndex < ops.size(); candidateIndex++) {
                PcodeOp candidate = ops.get(candidateIndex);
                if (!candidate.getSeqnum().getTarget().equals(
                    call.getSeqnum().getTarget())) {
                    continue;
                }
                if (candidate == call) {
                    callIndexAtAddress = candidateIndex;
                }
                if (binaryRegisterConstant(candidate, PcodeOp.INT_ADD, "SP", 2)) {
                    spAdds++;
                }
                if (binaryRegisterConstant(candidate, PcodeOp.INT_SUB, "SP", 2)) {
                    spSubs++;
                }
                if (candidate.getOpcode() == PcodeOp.STORE &&
                    candidate.getNumInputs() == 3 &&
                    isRegister(candidate.getInput(1), "SP") &&
                    isRegister(candidate.getInput(2), "RPC")) {
                    rpcStores++;
                }
                if (candidate.getOpcode() == PcodeOp.LOAD &&
                    outputRegister(candidate, "RPC") &&
                    candidate.getNumInputs() == 2 &&
                    isRegister(candidate.getInput(1), "SP")) {
                    rpcLoads++;
                }
                if (candidate.getOpcode() == PcodeOp.COPY &&
                    outputRegister(candidate, "XAR7")) {
                    xar7Copies++;
                    xar7CopyIndex = candidateIndex;
                }
            }
            if ("LCR".equalsIgnoreCase(mnemonic)) {
                require(spAdds == 1 && spSubs == 1 &&
                    rpcStores == 1 && rpcLoads == 1,
                    functionName + " completed LCR at " + instruction.getAddress() +
                        " lacks balanced RPC/SP state: adds=" + spAdds +
                        " subs=" + spSubs + " stores=" + rpcStores +
                        " loads=" + rpcLoads);
            }
        }
        return calls;
    }

    private void testCompletedCallPcode() {
        int lcr = 0;
        int ffc = 0;
        for (String name : RAW_CALLERS) {
            lcr += completedCalls(name, "LCR");
            ffc += completedCalls(name, "FFC");
        }
        require(lcr == 7, "expected seven completed LCR sites, got " + lcr);
        require(ffc == 4, "expected four completed FFC sites, got " + ffc);
        println("STACK_ARGUMENT_COMPLETED_LCR=" + lcr);
        println("STACK_ARGUMENT_COMPLETED_FFC=" + ffc);
        println("STACK_ARGUMENT_COMPLETED_CALL_SP_BALANCE=PASS");
    }

    private String directCallTarget(PcodeOpAST call) {
        if (call.getOpcode() != PcodeOp.CALL) {
            return null;
        }
        Instruction instruction = currentProgram.getListing().getInstructionContaining(
            call.getSeqnum().getTarget());
        if (instruction != null) {
            for (Address flow : instruction.getFlows()) {
                Function target = currentProgram.getFunctionManager().getFunctionAt(flow);
                if (target != null) {
                    return target.getName();
                }
            }
        }
        if (call.getNumInputs() > 0) {
            Function target = currentProgram.getFunctionManager().getFunctionAt(
                call.getInput(0).getAddress());
            if (target != null) {
                return target.getName();
            }
        }
        return null;
    }

    private int requireCallArity(DecompileResults results, String targetName,
            int arity, int expectedCount) {
        int count = 0;
        Iterator<PcodeOpAST> iterator = results.getHighFunction().getPcodeOps();
        while (iterator.hasNext()) {
            PcodeOpAST op = iterator.next();
            if (!targetName.equals(directCallTarget(op))) {
                continue;
            }
            count++;
            require(op.getNumInputs() == arity + 1,
                targetName + " call at " + op.getSeqnum().getTarget() +
                    " expected " + arity + " arguments, got " +
                    (op.getNumInputs() - 1));
        }
        require(count == expectedCount,
            "expected " + expectedCount + " calls to " + targetName +
                ", got " + count);
        return count;
    }

    private void rejectArtifacts(String name, String c) {
        String[] forbidden = {
            "in_stack_", "unaff_retaddr", "stack0x", "auStack_",
            "[10000]", "[999", "[249998]", "Could not recover jumptable",
            "Treating indirect jump as call"
        };
        for (String marker : forbidden) {
            require(!c.contains(marker), name + " contains " + marker + "\n" + c);
        }
    }

    private boolean containsEither(String text, String first, String second) {
        return text.contains(first) || text.contains(second);
    }

    private void testUntypedRecovery(String optimization) {
        Map<String, DecompileResults> results = new LinkedHashMap<>();
        StringBuilder noArgumentC = new StringBuilder();
        for (String name : NO_ARGUMENT_FUNCTIONS) {
            DecompileResults decompiled = decompile(function(name), "decompile");
            results.put(name, decompiled);
            require(decompiled.getHighFunction().getFunctionPrototype().getNumParams() == 0,
                name + " acquired phantom formal parameters");
            String c = decompiled.getDecompiledFunction().getC();
            require(c.contains(name + "(void)"),
                name + " no longer decompiles as a no-argument function\n" + c);
            rejectArtifacts(name, c);
            noArgumentC.append(c).append('\n');
        }

        String lcr = results.get("stack_noarg_lcr").getDecompiledFunction().getC();
        require(lcr.contains("stack_lcr_helper") && lcr.contains("0x11223344"),
            "direct LCR outgoing literal was not recovered\n" + lcr);
        requireCallArity(results.get("stack_noarg_lcr"), "stack_lcr_helper", 2, 1);

        String ffc = results.get("stack_noarg_ffc").getDecompiledFunction().getC();
        require(ffc.contains("stack_ffc_helper(stack_input,10)") ||
                ffc.contains("stack_ffc_helper(stack_input,0xa)"),
            "FFC outgoing literal 10 was not recovered\n" + ffc);
        requireCallArity(results.get("stack_noarg_ffc"), "stack_ffc_helper", 2, 1);

        String reuse = results.get("stack_reuse_ffc").getDecompiledFunction().getC();
        require(reuse.contains("stack_ffc_helper(stack_input,10)") &&
                containsEither(reuse, "stack_ffc_helper(stack_input,0x25)",
                    "stack_ffc_helper(stack_input,37)"),
            "reused FFC slot lost constants 10/37\n" + reuse);
        requireCallArity(results.get("stack_reuse_ffc"), "stack_ffc_helper", 2, 2);

        String division = results.get("stack_noarg_div").getDecompiledFunction().getC();
        require(division.contains("__c28xabi_divl(stack_input,10)") ||
                division.contains("__c28xabi_divl(stack_input,0xa)"),
            "division helper lost its divisor literal\n" + division);
        requireCallArity(results.get("stack_noarg_div"), "__c28xabi_divl", 2, 1);

        String conditional = results.get("stack_conditional_noarg")
            .getDecompiledFunction().getC();
        require(conditional.contains("if") && conditional.contains("stack_lcr_helper"),
            "conditional call/no-call rejoin was not recovered\n" + conditional);
        requireCallArity(results.get("stack_conditional_noarg"),
            "stack_lcr_helper", 2, 1);

        String escape = results.get("stack_escape_local").getDecompiledFunction().getC();
        require(escape.contains("stack_escape_helper") && escape.contains("&"),
            "escaped local lost its aliasing call\n" + escape);
        requireCallArity(results.get("stack_escape_local"),
            "stack_escape_helper", 2, 1);

        DecompileResults incoming = decompile(function("stack_incoming_live"), "decompile");
        require(incoming.getHighFunction().getFunctionPrototype().getNumParams() == 2,
            "genuine incoming stack parameter was reclassified as outgoing");
        String incomingC = incoming.getDecompiledFunction().getC();
        rejectArtifacts("stack_incoming_live", incomingC);
        require(incomingC.contains("param_2") && incomingC.contains("stack_lcr_helper") &&
                incomingC.contains("param_2"),
            "incoming stack parameter did not survive the nested call\n" + incomingC);
        requireCallArity(incoming, "stack_lcr_helper", 2, 1);

        for (String name : new String[] { "stack_ffc_helper", "__c28xabi_divl" }) {
            DecompileResults helper = decompile(function(name), "decompile");
            require(helper.getHighFunction().getFunctionPrototype().getNumParams() == 2,
                name + " did not infer two FFC arguments");
            String c = helper.getDecompiledFunction().getC();
            rejectArtifacts(name, c);
            require(c.contains("__ffc"), name + " lost its distinct convention\n" + c);
        }

        println("STACK_ARGUMENT_NOARG_FUNCTIONS=" + NO_ARGUMENT_FUNCTIONS.length);
        println("STACK_ARGUMENT_NO_PHANTOM_INPUTS_" + optimization + "=PASS");
        println("STACK_ARGUMENT_UNTYPED_OUTGOING_CONSTANTS=PASS");
        println("STACK_ARGUMENT_TRUE_INCOMING_PARAMETER=PASS");
        println("STACK_ARGUMENT_UNTYPED_FFC_ARITY=PASS");
    }

    private Function applyNaturalSignature(String name, String convention,
            DataType returnType, boolean expectCustom, String[] parameterNames,
            DataType... parameterTypes) throws Exception {
        require(parameterNames.length == parameterTypes.length,
            "parameter name/type mismatch for " + name);
        Function function = function(name);
        List<Variable> parameters = new ArrayList<>();
        for (int index = 0; index < parameterTypes.length; index++) {
            parameters.add(new ParameterImpl(parameterNames[index], parameterTypes[index],
                currentProgram));
        }
        function.updateFunction(convention,
            new ReturnParameterImpl(returnType, currentProgram), parameters,
            FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true,
            SourceType.USER_DEFINED);
        boolean applied = TMS320C28ScalarAbiAnalyzer.applyTypedScalarAbi(function);
        require(applied == expectCustom,
            name + " unexpected custom-storage decision: " + applied);
        require(function.hasCustomVariableStorage() == expectCustom,
            name + " custom-storage state mismatch");
        require(convention.equals(function.getCallingConventionName()),
            name + " lost convention " + convention + ": " +
                function.getCallingConventionName());
        return function;
    }

    private void requireStackDisjoint(Parameter[] parameters, int firstStack) {
        for (int i = firstStack; i < parameters.length; i++) {
            VariableStorage left = parameters[i].getVariableStorage();
            require(left.hasStackStorage(), parameters[i].getName() + " is not stack storage");
            int leftStart = left.getStackOffset();
            int leftEnd = leftStart + left.size();
            for (int j = i + 1; j < parameters.length; j++) {
                VariableStorage right = parameters[j].getVariableStorage();
                int rightStart = right.getStackOffset();
                int rightEnd = rightStart + right.size();
                require(leftEnd <= rightStart || rightEnd <= leftStart,
                    parameters[i].getName() + " overlaps " + parameters[j].getName() +
                        ": " + left + " vs " + right);
            }
        }
    }

    private void testTypedStorageAndAliases(String optimization) throws Exception {
        DataTypeManager dtm = currentProgram.getDataTypeManager();
        DataType s16 = new ShortDataType(dtm);
        DataType s32 = new LongDataType(dtm);
        DataType s64 = new LongLongDataType(dtm);
        DataType p16 = new PointerDataType(s16, dtm);
        DataType p32 = new PointerDataType(s32, dtm);
        DataType voidType = new VoidDataType(dtm);

        Function lcr = applyNaturalSignature("stack_lcr_helper",
            Function.DEFAULT_CALLING_CONVENTION_STRING, s32, true,
            new String[] { "left", "right" }, s32, s32);
        Function ffc = applyNaturalSignature("stack_ffc_helper", "__ffc", s32, true,
            new String[] { "left", "right" }, s32, s32);
        Function division = applyNaturalSignature("__c28xabi_divl", "__ffc", s32, true,
            new String[] { "dividend", "divisor" }, s32, s32);
        Function incoming = applyNaturalSignature("stack_incoming_live",
            Function.DEFAULT_CALLING_CONVENTION_STRING, s32, true,
            new String[] { "first", "second" }, s32, s32);
        Function mixed = applyNaturalSignature("stack_mixed_helper",
            Function.DEFAULT_CALLING_CONVENTION_STRING, s64, true,
            new String[] {
                "wide", "first_pointer", "second_pointer", "narrow_a",
                "narrow_b", "scalar", "stacked_wide"
            }, s64, p16, p16, s16, s16, s32, s64);
        Function escape = applyNaturalSignature("stack_escape_helper",
            Function.DEFAULT_CALLING_CONVENTION_STRING, voidType, false,
            new String[] { "pointer", "addend" }, p32, s32);

        requireRegisters(lcr.getReturn().getVariableStorage(), "ACC");
        requireRegisters(lcr.getParameter(0).getVariableStorage(), "ACC");
        requireStack(lcr.getParameter(1).getVariableStorage(), -8, 4,
            "LCR second 32-bit argument");
        for (Function helper : new Function[] { ffc, division }) {
            requireRegisters(helper.getReturn().getVariableStorage(), "ACC");
            requireRegisters(helper.getParameter(0).getVariableStorage(), "ACC");
            requireStack(helper.getParameter(1).getVariableStorage(), -4, 4,
                helper.getName() + " second 32-bit argument");
        }
        requireRegisters(incoming.getParameter(0).getVariableStorage(), "ACC");
        requireStack(incoming.getParameter(1).getVariableStorage(), -8, 4,
            "genuine incoming second argument");

        requireRegisters(mixed.getReturn().getVariableStorage(), "ACC", "P");
        requireRegisters(mixed.getParameter(0).getVariableStorage(), "ACC", "P");
        requireRegisters(mixed.getParameter(1).getVariableStorage(), "XAR4");
        requireRegisters(mixed.getParameter(2).getVariableStorage(), "XAR5");
        requireStack(mixed.getParameter(3).getVariableStorage(), -6, 2,
            "mixed narrow_a");
        requireStack(mixed.getParameter(4).getVariableStorage(), -8, 2,
            "mixed narrow_b");
        requireStack(mixed.getParameter(5).getVariableStorage(), -12, 4,
            "mixed scalar");
        requireStack(mixed.getParameter(6).getVariableStorage(), -20, 8,
            "mixed stacked_wide");
        requireStackDisjoint(mixed.getParameters(), 3);

        requireRegisters(escape.getParameter(0).getVariableStorage(), "XAR4");
        requireRegisters(escape.getParameter(1).getVariableStorage(), "ACC");
        require(escape.getReturn().getVariableStorage().isVoidStorage(),
            "escape helper must return void");

        DecompileResults mixedCaller = decompile(function("stack_mixed_caller"),
            "decompile");
        require(mixedCaller.getHighFunction().getFunctionPrototype().getNumParams() == 0,
            "typed mixed caller acquired phantom inputs");
        String mixedCallerC = mixedCaller.getDecompiledFunction().getC();
        rejectArtifacts("stack_mixed_caller typed", mixedCallerC);
        requireCallArity(mixedCaller, "stack_mixed_helper", 7, 1);
        require(mixedCallerC.contains("stack_mixed_helper") &&
                mixedCallerC.contains("0x3333") && mixedCallerC.contains("0x4444"),
            "typed mixed call lost its stack arguments\n" + mixedCallerC);

        DecompileResults mixedHelper = decompile(mixed, "decompile");
        require(mixedHelper.getHighFunction().getFunctionPrototype().getNumParams() == 7,
            "typed mixed helper lost parameters");
        rejectArtifacts("stack_mixed_helper typed",
            mixedHelper.getDecompiledFunction().getC());

        DecompileResults escapeCaller = decompile(function("stack_escape_local"),
            "decompile");
        String escapeC = escapeCaller.getDecompiledFunction().getC();
        rejectArtifacts("stack_escape_local typed", escapeC);
        require(escapeC.contains("stack_escape_helper") && escapeC.contains("&") &&
                containsEither(escapeC, ",0xd)", ",13)"),
            "typed escaped local lost valid aliasing\n" + escapeC);

        DecompileResults incomingTyped = decompile(incoming, "decompile");
        String incomingC = incomingTyped.getDecompiledFunction().getC();
        rejectArtifacts("stack_incoming_live typed", incomingC);
        require(incomingTyped.getHighFunction().getFunctionPrototype().getNumParams() == 2 &&
                incomingC.contains("second") && incomingC.contains("stack_lcr_helper"),
            "typed incoming stack parameter did not survive nested call\n" + incomingC);

        for (String name : NO_ARGUMENT_FUNCTIONS) {
            DecompileResults noarg = decompile(function(name), "decompile");
            require(noarg.getHighFunction().getFunctionPrototype().getNumParams() == 0,
                name + " acquired an input after typed callee propagation");
            rejectArtifacts(name + " after typed callees",
                noarg.getDecompiledFunction().getC());
        }

        println("STACK_ARGUMENT_LCR_FIRST_32_STACK_BYTES=-8");
        println("STACK_ARGUMENT_FFC_FIRST_32_STACK_BYTES=-4");
        println("STACK_ARGUMENT_MIXED_TYPE_PRIORITY=PASS");
        println("STACK_ARGUMENT_INCOMING_OUTGOING_DISJOINT=PASS");
        println("STACK_ARGUMENT_ESCAPED_LOCAL_ALIAS=PASS");
        println("STACK_ARGUMENT_TYPED_REDECOMPILE_" + optimization + "=PASS");
    }
}
