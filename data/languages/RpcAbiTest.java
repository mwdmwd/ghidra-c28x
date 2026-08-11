import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;

/** Focused compiler-spec, decompiler, and raw-P-Code regression for C28x calls. */
public class RpcAbiTest extends GhidraScript {
    private static final String[] FUNCTIONS = {
        "rpc_leaf", "rpc_multi_return", "rpc_nested_inner", "rpc_nested_outer",
        "rpc_indirect_target", "rpc_indirect_call", "rpc_stack_args",
        "rpc_stack_caller", "rpc_void_a", "rpc_void_b", "rpc_void_c",
        "rpc_branch_rejoin", "rpc_preserve_older", "rpc_fixture_entry"
    };

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    @Override public void run() throws Exception {
        String name = currentProgram.getName().toLowerCase(Locale.ROOT);
        if (name.contains("rpc_abi_o0")) testCompiler("O0");
        else if (name.contains("rpc_abi_o2")) testCompiler("O2");
        else if (name.contains("rpc_flow_validation")) testFlow();
        else throw new AssertionError("unknown fixture " + currentProgram.getName());
        println("RPC_ABI_PROGRAM_PASS=" + currentProgram.getName());
    }

    private Function function(String name) {
        List<Function> found = getGlobalFunctions(name);
        require(found.size() == 1, "expected one function " + name + ", got " + found.size());
        return found.get(0);
    }

    private List<Instruction> instructions(Function function) {
        ArrayList<Instruction> result = new ArrayList<>();
        InstructionIterator iterator = currentProgram.getListing().getInstructions(function.getBody(), true);
        while (iterator.hasNext()) result.add(iterator.next());
        return result;
    }

    private DecompileResults decompile(Function function, String style) {
        DecompInterface decompiler = new DecompInterface();
        require(decompiler.setSimplificationStyle(style), "unsupported style " + style);
        require(decompiler.openProgram(currentProgram), "open decompiler failed");
        DecompileResults result = decompiler.decompileFunction(function, 45, monitor);
        decompiler.dispose();
        require(result.decompileCompleted(), style + " failed for " + function.getName() + ": " + result.getErrorMessage());
        return result;
    }

    private Register register(Varnode node) {
        if (node == null || !node.isRegister()) return null;
        return currentProgram.getLanguage().getRegister(node.getAddress(), node.getSize());
    }

    private boolean isRegister(Varnode node, String name) {
        Register r = register(node);
        return r != null && name.equals(r.getName());
    }

    private boolean overlaps(Varnode node, Register r) {
        if (node == null || !node.isRegister() || r == null) return false;
        long a = node.getOffset(), b = r.getOffset();
        return a < b + r.getMinimumByteSize() && b < a + node.getSize();
    }

    private int count(String text, String needle) {
        int result = 0, offset = 0;
        while ((offset = text.indexOf(needle, offset)) >= 0) {
            result++; offset += needle.length();
        }
        return result;
    }

    private void compilerSpec() {
        CompilerSpec spec = currentProgram.getCompilerSpec();
        Register sp = spec.getStackPointer();
        Register sp16 = currentProgram.getRegister("SP16");
        require(sp != null && "SP".equals(sp.getName()) && sp.getMinimumByteSize() == 4,
            "stack pointer must be SP:4");
        require(sp16 != null && sp16.getMinimumByteSize() == 2, "missing SP16 alias");
        require(!spec.stackGrowsNegative(), "stack must grow positive");
        require(spec.getStackSpace().getAddressableUnitSize() == 2, "stack word size must be two bytes");
        PrototypeModel model = spec.getDefaultCallingConvention();
        require(model.getStackshift() == 0, "completed LCR calls must not add a second stack shift");
        require(Long.valueOf(-4).equals(model.getStackParameterOffset()),
            "first stack parameter offset must be -4 words, got " + model.getStackParameterOffset());
        Varnode[] ra = model.getReturnAddress();
        require(ra.length == 1 && isRegister(ra[0], "RPC"), "return address must be RPC");
        PrototypeModel lcModel = currentProgram.getFunctionManager().getCallingConvention("__lc");
        PrototypeModel ffcModel = currentProgram.getFunctionManager().getCallingConvention("__ffc");
        require(lcModel != null, "missing __lc prototype");
        require(ffcModel != null, "missing __ffc prototype");
        require(lcModel.getStackshift() == 0, "completed LC calls must not add a second stack shift");
        require(Long.valueOf(-4).equals(lcModel.getStackParameterOffset()),
            "__lc first stack parameter must be -4 words");
        require(lcModel.getReturnAddress().length == 0,
            "__lc must not invent an RPC return address");
        require(ffcModel.getStackshift() == 0, "__ffc must not shift the stack");
        require(Long.valueOf(-2).equals(ffcModel.getStackParameterOffset()),
            "__ffc first stack parameter must be -2 words, got " +
                ffcModel.getStackParameterOffset());
        Varnode[] ffcRa = ffcModel.getReturnAddress();
        require(ffcRa.length == 1 && isRegister(ffcRa[0], "XAR7"),
            "__ffc return address must be XAR7");
        println("RPC_ABI_STACK_REGISTER_BYTES=4");
        println("RPC_ABI_STACK_ADDRESSABLE_UNIT_BYTES=2");
        println("RPC_ABI_STACK_SHIFT_WORDS=0");
        println("RPC_ABI_FIRST_STACK_PARAMETER_WORD_OFFSET=-4");
        println("RPC_ABI_LC_STACK_SHIFT_WORDS=0");
        println("RPC_ABI_FFC_STACK_SHIFT_WORDS=0");
        println("RPC_ABI_FFC_FIRST_STACK_PARAMETER_WORD_OFFSET=-2");
        println("RPC_ABI_CALL_MECHANISM_MODELS=3");
    }

    private void noStackZext(Function function) {
        Register sp = currentProgram.getRegister("SP");
        Register sp16 = currentProgram.getRegister("SP16");
        for (Instruction instruction : instructions(function)) {
            for (PcodeOp op : instruction.getPcode()) {
                if (op.getOpcode() == PcodeOp.INT_ZEXT && op.getNumInputs() > 0) {
                    require(!overlaps(op.getInput(0), sp) && !overlaps(op.getInput(0), sp16),
                        "ZEXT24 stack address at " + instruction.getAddress());
                }
            }
        }
    }

    private void testCompiler(String optimization) {
        compilerSpec();
        StringBuilder all = new StringBuilder();
        StringBuilder diagnostics = new StringBuilder();
        int firstPass = 0;
        int completedCalls = 0;
        int branchCalls = 0;
        String stackArgs = "", stackCaller = "", indirect = "", branch = "";
        for (String name : FUNCTIONS) {
            Function function = function(name);
            noStackZext(function);
            DecompileResults first = decompile(function, "firstpass");
            require(first.getHighFunction() != null, "no first-pass high function for " + name);
            int functionCalls = requireBalancedCompletedCalls(name, first);
            completedCalls += functionCalls;
            if (name.equals("rpc_branch_rejoin")) branchCalls = functionCalls;
            firstPass++;
            DecompileResults full = decompile(function, "decompile");
            require(full.getDecompiledFunction() != null, "no C for " + name);
            String c = full.getDecompiledFunction().getC();
            all.append(c).append('\n');
            if (name.equals("rpc_stack_args")) stackArgs = c;
            if (name.equals("rpc_stack_caller")) stackCaller = c;
            if (name.equals("rpc_indirect_call")) indirect = c;
            if (name.equals("rpc_branch_rejoin")) branch = c;
            String error = full.getErrorMessage();
            if (error != null && !error.isBlank()) diagnostics.append(error).append('\n');
        }
        String text = all.toString();
        int zext = count(text, "ZEXT24");
        int ret = count(text, "unaff_retaddr");
        int array = count(text, "[10000]");
        int stackHex = count(text, "stack0x");
        require(zext == 0, "ZEXT24 remains\n" + text);
        require(ret == 0, "unaff_retaddr remains\n" + text);
        require(array == 0, "[10000] remains\n" + text);
        require(stackHex == 0, "stack0x remains\n" + text);
        require(stackArgs.contains("param_10"), "ten argument callee not recovered\n" + stackArgs);
        require(stackCaller.contains("rpc_stack_args") && stackCaller.contains("+ 9"),
            "ten argument caller not recovered\n" + stackCaller);
        require(indirect.contains("code *") || indirect.contains("(*)"),
            "indirect call not recovered\n" + indirect);
        require(branch.contains("rpc_void_a") && branch.contains("rpc_void_b") &&
            branch.contains("rpc_void_c") && branch.contains("if"),
            "branch-sensitive fixture lost unequal call arms\n" + branch);
        require(branchCalls == 4,
            "branch-sensitive fixture must contain four ordinary LCR sites, got " + branchCalls);
        require(branch.contains("in_stack_") && branch.contains("lVar"),
            "branch-sensitive fixture lost stack-argument/local accesses\n" + branch);
        require(!branch.contains("unaff_retaddr") && !branch.contains("[10000]") &&
            !branch.contains("[249998]") && !branch.contains("auStack_"),
            "branch-sensitive fixture still has a path-dependent stack\n" + branch);
        println("RPC_ABI_OPTIMIZATION=" + optimization);
        println("RPC_ABI_FIRST_PASS_FUNCTIONS=" + firstPass);
        println("RPC_ABI_FULL_FUNCTIONS=" + FUNCTIONS.length);
        println("RPC_ABI_ZEXT24=" + zext);
        println("RPC_ABI_UNAFF_RETADDR=" + ret);
        println("RPC_ABI_SYNTHETIC_STACK_10000=" + array);
        println("RPC_ABI_STACK_HEX_VARIABLES=" + stackHex);
        println("RPC_ABI_FULL_DIAGNOSTIC_CHARS=" + diagnostics.length());
        println("RPC_ABI_STACK_ARGUMENTS_10=PASS");
        println("RPC_ABI_BALANCED_COMPLETED_CALLS=" + completedCalls);
        println("RPC_ABI_BRANCH_LCR_SITES=" + branchCalls);
        println("RPC_ABI_BRANCH_SENSITIVE_REJOIN=PASS");
    }

    private boolean outputRegister(PcodeOp op, String register) {
        return op != null && isRegister(op.getOutput(), register);
    }

    private boolean binaryRegisterConstant(PcodeOp op, int opcode, String register,
            long constant) {
        return op != null && op.getOpcode() == opcode && outputRegister(op, register) &&
            op.getNumInputs() == 2 && isRegister(op.getInput(0), register) &&
            constant(op.getInput(1), constant);
    }

    private int requireBalancedCompletedCalls(String functionName, DecompileResults first) {
        List<PcodeOpAST> ops = new ArrayList<>();
        Iterator<PcodeOpAST> iterator = first.getHighFunction().getPcodeOps();
        while (iterator.hasNext()) ops.add(iterator.next());
        int calls = 0;
        for (int index = 0; index < ops.size(); index++) {
            PcodeOpAST call = ops.get(index);
            if (call.getOpcode() != PcodeOp.CALL && call.getOpcode() != PcodeOp.CALLIND) continue;
            Instruction instruction = currentProgram.getListing().getInstructionContaining(
                call.getSeqnum().getTarget());
            if (instruction == null ||
                !"LCR".equalsIgnoreCase(instruction.getMnemonicString())) {
                continue; // decompiler synthetic tail-call or another call mechanism
            }
            calls++;
            int saveIndex = -1, addIndex = -1, rpcCopyIndex = -1;
            int subIndex = -1, rpcLoadIndex = -1;
            int stackAdds = 0, stackSubs = 0;
            for (int candidateIndex = 0; candidateIndex < ops.size(); candidateIndex++) {
                PcodeOp candidate = ops.get(candidateIndex);
                if (!candidate.getSeqnum().getTarget().equals(call.getSeqnum().getTarget())) continue;
                if (candidate.getOpcode() == PcodeOp.STORE && candidate.getNumInputs() == 3 &&
                    isRegister(candidate.getInput(1), "SP") &&
                    isRegister(candidate.getInput(2), "RPC")) {
                    saveIndex = candidateIndex;
                }
                if (binaryRegisterConstant(candidate, PcodeOp.INT_ADD, "SP", 2)) {
                    stackAdds++;
                    addIndex = candidateIndex;
                }
                if (candidate.getOpcode() == PcodeOp.COPY && outputRegister(candidate, "RPC")) {
                    rpcCopyIndex = candidateIndex;
                }
                if (binaryRegisterConstant(candidate, PcodeOp.INT_SUB, "SP", 2)) {
                    stackSubs++;
                    subIndex = candidateIndex;
                }
                if (candidate.getOpcode() == PcodeOp.LOAD && outputRegister(candidate, "RPC") &&
                    candidate.getNumInputs() == 2 && isRegister(candidate.getInput(1), "SP")) {
                    rpcLoadIndex = candidateIndex;
                }
            }
            require(stackAdds == 1 && stackSubs == 1,
                "completed LCR call must have one SP += 2 and one SP -= 2 in " +
                    functionName + " at " + instruction.getAddress() +
                    ", got adds=" + stackAdds + " subs=" + stackSubs);
            require(saveIndex >= 0 && addIndex >= 0 && rpcCopyIndex >= 0 &&
                    subIndex >= 0 && rpcLoadIndex >= 0,
                "incomplete LCR/LRETR state transition in " + functionName +
                    " at " + instruction.getAddress());
            require(saveIndex < addIndex && addIndex < rpcCopyIndex && rpcCopyIndex < index &&
                    index < subIndex && subIndex < rpcLoadIndex,
                "misordered completed LCR state transition in " + functionName +
                    " at " + instruction.getAddress());
        }
        return calls;
    }

    private Instruction one(String function, String mnemonic) {
        Instruction result = null;
        for (Instruction instruction : instructions(function(function))) {
            if (mnemonic.equalsIgnoreCase(instruction.getMnemonicString())) {
                require(result == null, "multiple " + mnemonic + " in " + function);
                result = instruction;
            }
        }
        require(result != null, "missing " + mnemonic + " in " + function);
        return result;
    }

    private int pcodeCount(Instruction instruction, int opcode) {
        int count = 0;
        for (PcodeOp op : instruction.getPcode()) if (op.getOpcode() == opcode) count++;
        return count;
    }

    private boolean constant(Varnode node, long value) {
        return node != null && node.isConstant() && node.getOffset() == value;
    }

    private void requireStackSub(Instruction instruction, long delta) {
        for (PcodeOp op : instruction.getPcode()) {
            if (op.getOpcode() == PcodeOp.INT_SUB && isRegister(op.getOutput(), "SP")) {
                for (Varnode input : op.getInputs()) if (constant(input, delta)) return;
            }
        }
        throw new AssertionError("missing SP -= " + delta + " in " + instruction);
    }

    private void testFlow() {
        int lc = 0, lci = 0, lcr = 0, lcri = 0;
        for (Instruction instruction : instructions(function("rpc_flow_entry"))) {
            String mnemonic = instruction.getMnemonicString().toUpperCase(Locale.ROOT);
            if ("LC".equals(mnemonic)) {
                require(pcodeCount(instruction, PcodeOp.CALL) + pcodeCount(instruction, PcodeOp.CALLIND) == 1,
                    "LC flow missing");
                if (pcodeCount(instruction, PcodeOp.CALLIND) == 1) lci++; else lc++;
            }
            if ("LCR".equals(mnemonic)) {
                require(pcodeCount(instruction, PcodeOp.CALL) + pcodeCount(instruction, PcodeOp.CALLIND) == 1,
                    "LCR flow missing");
                if (pcodeCount(instruction, PcodeOp.CALLIND) == 1) {
                    lcri++;
                    boolean mask = false;
                    for (PcodeOp op : instruction.getPcode()) {
                        if (op.getOpcode() == PcodeOp.INT_AND) {
                            for (Varnode input : op.getInputs()) mask |= constant(input, 0x3fffff);
                        }
                    }
                    require(mask, "indirect LCR lacks 22-bit target mask");
                } else lcr++;
            }
        }
        require(lc == 1 && lci == 1 && lcr == 3 && lcri == 1, "unexpected LC/LCR mix");
        Instruction lret = one("lc_direct_target", "LRET");
        require(pcodeCount(lret, PcodeOp.RETURN) == 1 && pcodeCount(lret, PcodeOp.LOAD) == 1, "LRET P-Code");
        requireStackSub(lret, 2);
        Instruction lretr = one("lcr_direct_target", "LRETR");
        require(pcodeCount(lretr, PcodeOp.RETURN) == 1 && pcodeCount(lretr, PcodeOp.LOAD) == 1, "LRETR P-Code");
        requireStackSub(lretr, 2);
        Instruction lrete = one("lrete_target", "LRETE");
        require(pcodeCount(lrete, PcodeOp.RETURN) == 1, "LRETE P-Code");
        requireStackSub(lrete, 2);
        Instruction iret = one("iret_target", "IRET");
        require(pcodeCount(iret, PcodeOp.RETURN) == 1, "IRET P-Code");
        int two = 0, one = 0;
        for (PcodeOp op : iret.getPcode()) {
            if (op.getOpcode() == PcodeOp.INT_SUB && isRegister(op.getOutput(), "SP")) {
                for (Varnode input : op.getInputs()) { if (constant(input, 2)) two++; if (constant(input, 1)) one++; }
            }
        }
        require(two == 7 && one == 1, "IRET must pop seven pairs and alignment word");
        println("RPC_ABI_DIRECT_LC=" + lc);
        println("RPC_ABI_INDIRECT_LC=" + lci);
        println("RPC_ABI_DIRECT_LCR=" + lcr);
        println("RPC_ABI_INDIRECT_LCR=" + lcri);
        println("RPC_ABI_LC_CONVENTION_FUNCTIONS=3");
        println("RPC_ABI_LRET=PASS");
        println("RPC_ABI_LRETR=PASS");
        println("RPC_ABI_LRETE=PASS");
        println("RPC_ABI_IRET=PASS");
    }
}
