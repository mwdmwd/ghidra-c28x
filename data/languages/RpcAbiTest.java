import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.plugin.core.analysis.TMS320C28ScalarAbiAnalyzer;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.LongDataType;
import ghidra.program.model.data.LongLongDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.ShortDataType;
import ghidra.program.model.data.UnsignedLongDataType;
import ghidra.program.model.data.UnsignedLongLongDataType;
import ghidra.program.model.data.UnsignedShortDataType;
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
import ghidra.program.model.pcode.FunctionPrototype;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

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

    private void testCompiler(String optimization) throws Exception {
        compilerSpec();
        testScalarAbi(optimization);
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

    private Function applyNaturalSignature(String name, DataType returnType,
            boolean expectCustomStorage, String[] parameterNames, DataType... parameterTypes)
            throws Exception {
        require(parameterNames.length == parameterTypes.length,
            "parameter name/type mismatch for " + name);
        Function function = function(name);
        List<Variable> parameters = new ArrayList<>();
        for (int index = 0; index < parameterTypes.length; index++) {
            parameters.add(new ParameterImpl(parameterNames[index], parameterTypes[index],
                currentProgram));
        }
        function.updateFunction(Function.DEFAULT_CALLING_CONVENTION_STRING,
            new ReturnParameterImpl(returnType, currentProgram), parameters,
            FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED);
        boolean applied = TMS320C28ScalarAbiAnalyzer.applyTypedScalarAbi(function);
        require(applied == expectCustomStorage,
            "unexpected scalar ABI custom-storage decision for " + name + ": " + applied);
        require(function.hasCustomVariableStorage() == expectCustomStorage,
            "unexpected custom-storage state for " + name);
        require(Function.DEFAULT_CALLING_CONVENTION_STRING.equals(
            function.getCallingConventionName()),
            "scalar ABI update lost default calling convention for " + name + ": " +
                function.getCallingConventionName());
        return function;
    }

    private String[] registerNames(VariableStorage storage) {
        Varnode[] varnodes = storage.getVarnodes();
        String[] result = new String[varnodes.length];
        for (int index = 0; index < varnodes.length; index++) {
            Register register = register(varnodes[index]);
            result[index] = register == null ? "<non-register>" : register.getName();
        }
        return result;
    }

    private void requireRegisters(VariableStorage storage, String... expected) {
        String[] actual = registerNames(storage);
        require(java.util.Arrays.equals(actual, expected),
            "expected storage " + java.util.Arrays.toString(expected) + ", got " +
                java.util.Arrays.toString(actual) + " (" + storage + ")");
    }

    private void requireStack(VariableStorage storage, int offset, int size, String context) {
        require(storage.hasStackStorage() && storage.getStackOffset() == offset &&
            storage.size() == size,
            context + " expected Stack[" + offset + "]:" + size + ", got " + storage);
    }

    private void requireNaturalParameters(Function function, int count) {
        Parameter[] parameters = function.getParameters();
        require(parameters.length == count,
            function.getName() + " expected " + count + " parameters, got " +
                parameters.length);
        for (Parameter parameter : parameters) {
            require(!parameter.isAutoParameter(),
                function.getName() + " invented auto parameter " + parameter);
        }
    }

    private void requireType(DataType actual, DataType expected, String context) {
        require(actual.isEquivalent(expected),
            context + " expected " + expected.getDisplayName() + ", got " +
                actual.getDisplayName());
    }

    private void requireHighPrototype(DecompileResults results, Function function) {
        require(results.getHighFunction() != null,
            "missing HighFunction for " + function.getName());
        FunctionPrototype prototype = results.getHighFunction().getFunctionPrototype();
        require(prototype.getNumParams() == function.getParameterCount(),
            "HighFunction parameter count mismatch for " + function.getName() + ": " +
                prototype.getNumParams() + " vs " + function.getParameterCount());
        require(prototype.getReturnStorage().equals(function.getReturn().getVariableStorage()),
            "HighFunction return storage mismatch for " + function.getName() + ": " +
                prototype.getReturnStorage() + " vs " +
                function.getReturn().getVariableStorage());
        requireType(prototype.getReturnType(), function.getReturnType(),
            function.getName() + " HighFunction return type");
        Parameter[] parameters = function.getParameters();
        for (int index = 0; index < parameters.length; index++) {
            HighSymbol symbol = prototype.getParam(index);
            require(symbol != null, "missing HighFunction parameter " + index + " for " +
                function.getName());
            require(symbol.getStorage().equals(parameters[index].getVariableStorage()),
                "HighFunction storage mismatch for " + function.getName() + " parameter " +
                    index + ": " + symbol.getStorage() + " vs " +
                    parameters[index].getVariableStorage());
            requireType(symbol.getDataType(), parameters[index].getDataType(),
                function.getName() + " HighFunction parameter " + index);
        }
    }

    private String directCallTarget(PcodeOpAST call) {
        if (call.getOpcode() != PcodeOp.CALL) return null;
        Instruction instruction = currentProgram.getListing().getInstructionContaining(
            call.getSeqnum().getTarget());
        if (instruction != null) {
            for (Address flow : instruction.getFlows()) {
                Function target = currentProgram.getFunctionManager().getFunctionAt(flow);
                if (target != null) return target.getName();
            }
        }
        Varnode targetNode = call.getNumInputs() == 0 ? null : call.getInput(0);
        if (targetNode != null) {
            Function target = currentProgram.getFunctionManager().getFunctionAt(
                targetNode.getAddress());
            if (target != null) return target.getName();
        }
        return null;
    }

    private int requireCallArity(DecompileResults results, String targetName, int arity,
            int expectedCount) {
        int count = 0;
        Iterator<PcodeOpAST> iterator = results.getHighFunction().getPcodeOps();
        while (iterator.hasNext()) {
            PcodeOpAST op = iterator.next();
            if (!targetName.equals(directCallTarget(op))) continue;
            count++;
            require(op.getNumInputs() == arity + 1,
                targetName + " call at " + op.getSeqnum().getTarget() + " expected " +
                    arity + " logical arguments, got " + (op.getNumInputs() - 1));
        }
        require(count == expectedCount,
            "expected " + expectedCount + " calls to " + targetName + ", got " + count);
        return count;
    }

    private void requireModelStorage(PrototypeModel model, DataType returnType,
            DataType[] parameterTypes, String[] returnRegisters,
            String[][] parameterRegisters) {
        DataType[] types = new DataType[parameterTypes.length + 1];
        types[0] = returnType;
        System.arraycopy(parameterTypes, 0, types, 1, parameterTypes.length);
        VariableStorage[] storage = model.getStorageLocations(currentProgram, types, false);
        require(storage.length == types.length, "compiler model storage count mismatch");
        requireRegisters(storage[0], returnRegisters);
        for (int index = 0; index < parameterRegisters.length; index++) {
            requireRegisters(storage[index + 1], parameterRegisters[index]);
        }
    }

    private void testScalarAbi(String optimization) throws Exception {
        DataTypeManager dtm = currentProgram.getDataTypeManager();
        DataType s16 = new ShortDataType(dtm);
        DataType u16 = new UnsignedShortDataType(dtm);
        DataType s32 = new LongDataType(dtm);
        DataType u32 = new UnsignedLongDataType(dtm);
        DataType s64 = new LongLongDataType(dtm);
        DataType u64 = new UnsignedLongLongDataType(dtm);
        DataType p16 = new PointerDataType(s16, dtm);

        Function oneS16 = applyNaturalSignature("rpc_one_s16", s16, false,
            new String[] { "value" }, s16);
        Function oneU16 = applyNaturalSignature("rpc_one_u16", u16, false,
            new String[] { "value" }, u16);
        Function fourS16 = applyNaturalSignature("rpc_four_s16", s16, true,
            new String[] { "a", "b", "c", "d" }, s16, s16, s16, s16);
        Function oneS32 = applyNaturalSignature("rpc_one_s32", s32, false,
            new String[] { "value" }, s32);
        Function idS64 = applyNaturalSignature("rpc_id_s64", s64, true,
            new String[] { "value" }, s64);
        Function arithS64 = applyNaturalSignature("rpc_arith_s64", s64, true,
            new String[] { "value" }, s64);
        Function arithU64 = applyNaturalSignature("rpc_arith_u64", u64, true,
            new String[] { "value" }, u64);
        Function twoS64 = applyNaturalSignature("rpc_two_s64", s64, true,
            new String[] { "first", "second" }, s64, s64);
        Function twoU64 = applyNaturalSignature("rpc_two_u64", u64, true,
            new String[] { "first", "second" }, u64, u64);
        Function mixed = applyNaturalSignature("rpc_mixed_s64", s64, true,
            new String[] { "a", "b", "c", "d" }, s32, s64, s16, p16);
        Function divS64 = applyNaturalSignature("rpc_div_s64", s64, true,
            new String[] { "dividend", "divisor" }, s64, s64);
        Function divU64 = applyNaturalSignature("rpc_div_u64", u64, true,
            new String[] { "dividend", "divisor" }, u64, u64);
        Function calls16 = applyNaturalSignature("rpc_calls16", s16, false,
            new String[] { "choose" }, s16);
        Function calls64 = applyNaturalSignature("rpc_calls64", s64, true,
            new String[] { "x", "y", "c", "pointer" }, s64, s64, s16, p16);
        Function scalarEntry = applyNaturalSignature("rpc_scalar_fixture_entry", s64, true,
            new String[] { "choose" }, s16);
        Function helperS64 = applyNaturalSignature("__c28xabi_divll", s64, true,
            new String[] { "dividend", "divisor" }, s64, s64);
        Function helperU64 = applyNaturalSignature("__c28xabi_divull", u64, true,
            new String[] { "dividend", "divisor" }, u64, u64);

        requireNaturalParameters(oneS16, 1);
        requireRegisters(oneS16.getReturn().getVariableStorage(), "AL");
        requireRegisters(oneS16.getParameter(0).getVariableStorage(), "AL");
        requireNaturalParameters(oneU16, 1);
        requireRegisters(oneU16.getReturn().getVariableStorage(), "AL");
        requireRegisters(oneU16.getParameter(0).getVariableStorage(), "AL");

        requireNaturalParameters(fourS16, 4);
        requireRegisters(fourS16.getReturn().getVariableStorage(), "AL");
        requireRegisters(fourS16.getParameter(0).getVariableStorage(), "AL");
        requireRegisters(fourS16.getParameter(1).getVariableStorage(), "AH");
        requireRegisters(fourS16.getParameter(2).getVariableStorage(), "AR4");
        requireRegisters(fourS16.getParameter(3).getVariableStorage(), "AR5");

        requireNaturalParameters(oneS32, 1);
        requireRegisters(oneS32.getReturn().getVariableStorage(), "ACC");
        requireRegisters(oneS32.getParameter(0).getVariableStorage(), "ACC");

        for (Function function : new Function[] {
            idS64, arithS64, arithU64, twoS64, twoU64, mixed, divS64, divU64,
            calls64, scalarEntry, helperS64, helperU64
        }) {
            requireRegisters(function.getReturn().getVariableStorage(), "ACC", "P");
            require(!function.getReturn().getVariableStorage().intersects(
                currentProgram.getRegister("XAR4")),
                function.getName() + " invented an XAR4 hidden result");
            require(!function.getReturn().getVariableStorage().intersects(
                currentProgram.getRegister("XAR6")),
                function.getName() + " invented an XAR6 hidden result");
        }

        requireNaturalParameters(idS64, 1);
        requireRegisters(idS64.getParameter(0).getVariableStorage(), "ACC", "P");
        requireNaturalParameters(twoS64, 2);
        requireRegisters(twoS64.getParameter(0).getVariableStorage(), "ACC", "P");
        requireStack(twoS64.getParameter(1).getVariableStorage(), -12, 8,
            "rpc_two_s64 second argument");
        requireNaturalParameters(twoU64, 2);
        requireRegisters(twoU64.getParameter(0).getVariableStorage(), "ACC", "P");
        requireStack(twoU64.getParameter(1).getVariableStorage(), -12, 8,
            "rpc_two_u64 second argument");

        requireNaturalParameters(mixed, 4);
        requireStack(mixed.getParameter(0).getVariableStorage(), -8, 4,
            "rpc_mixed_s64 a");
        requireRegisters(mixed.getParameter(1).getVariableStorage(), "ACC", "P");
        requireRegisters(mixed.getParameter(2).getVariableStorage(), "AR5");
        requireRegisters(mixed.getParameter(3).getVariableStorage(), "XAR4");

        requireNaturalParameters(calls64, 4);
        requireRegisters(calls64.getParameter(0).getVariableStorage(), "ACC", "P");
        requireStack(calls64.getParameter(1).getVariableStorage(), -12, 8,
            "rpc_calls64 y");
        requireRegisters(calls64.getParameter(2).getVariableStorage(), "AR5");
        requireRegisters(calls64.getParameter(3).getVariableStorage(), "XAR4");

        for (Function helper : new Function[] { helperS64, helperU64 }) {
            requireNaturalParameters(helper, 2);
            requireRegisters(helper.getParameter(0).getVariableStorage(), "ACC", "P");
            requireStack(helper.getParameter(1).getVariableStorage(), -12, 8,
                helper.getName() + " divisor");
        }
        requireType(helperS64.getReturnType(), s64, "signed division helper return");
        requireType(helperS64.getParameter(0).getDataType(), s64,
            "signed division helper dividend");
        requireType(helperU64.getReturnType(), u64, "unsigned division helper return");
        requireType(helperU64.getParameter(0).getDataType(), u64,
            "unsigned division helper dividend");

        PrototypeModel model = currentProgram.getCompilerSpec().getDefaultCallingConvention();
        requireModelStorage(model, s16, new DataType[] { s16 },
            new String[] { "AL" }, new String[][] { { "AL" } });
        requireModelStorage(model, s16, new DataType[] { s16, s16, s16, s16 },
            new String[] { "AL" }, new String[][] {
                { "AL" }, { "AH" }, { "AR4" }, { "AR5" }
            });
        requireModelStorage(model, s32, new DataType[] { s32 },
            new String[] { "ACC" }, new String[][] { { "ACC" } });
        VariableStorage[] output64 = model.getStorageLocations(currentProgram,
            new DataType[] { s64 }, false);
        require(output64.length == 1, "64-bit output model returned extra storage");
        requireRegisters(output64[0], "ACC", "P");

        String[] decompileNames = {
            "rpc_one_s16", "rpc_one_u16", "rpc_four_s16", "rpc_one_s32",
            "rpc_id_s64", "rpc_two_s64", "rpc_mixed_s64", "rpc_div_s64",
            "rpc_div_u64", "rpc_calls16", "rpc_calls64", "rpc_scalar_fixture_entry"
        };
        Map<String, DecompileResults> results = new LinkedHashMap<>();
        Map<String, String> text = new LinkedHashMap<>();
        for (String name : decompileNames) {
            Function function = function(name);
            DecompileResults decompiled = decompile(function, "decompile");
            require(decompiled.getDecompiledFunction() != null, "no scalar C for " + name);
            requireHighPrototype(decompiled, function);
            results.put(name, decompiled);
            text.put(name, decompiled.getDecompiledFunction().getC());
        }

        String calls16Text = text.get("rpc_calls16");
        String calls16Compact = calls16Text.replaceAll("\\s+", "");
        require(!calls16Text.contains("CONCAT22") &&
            !calls16Text.contains("extraout_AH") && !calls16Text.contains("in_AH"),
            "16-bit calls still depend on stale AH\n" + calls16Text);
        for (String call : new String[] {
            "rpc_one_s16(6)", "rpc_one_s16(1)", "rpc_one_s16(10)",
            "rpc_one_s16(0)", "rpc_one_u16(0xfff0)",
            "rpc_four_s16(1,2,3,4)", "rpc_four_s16(5,6,7,8)"
        }) {
            require(calls16Compact.contains(call),
                "missing plain 16-bit call " + call + "\n" + calls16Text);
        }
        require(calls16Compact.contains("rpc_one_s16(-7)") ||
            calls16Compact.contains("rpc_one_s16(0xfff9)"),
            "missing negative signed 16-bit call\n" + calls16Text);
        String fourText = text.get("rpc_four_s16");
        require(!fourText.contains("in_AH") && fourText.contains("short b") &&
            fourText.contains("short c") && fourText.contains("short d"),
            "four-scalar callee lost AH/AR4/AR5 parameters\n" + fourText);
        String one32Text = text.get("rpc_one_s32");
        require(one32Text.contains("long rpc_one_s32(long value)") &&
            one32Text.contains("0x12345678"),
            "32-bit ACC regression was truncated\n" + one32Text);

        requireCallArity(results.get("rpc_calls16"), "rpc_one_s16", 1, 6);
        requireCallArity(results.get("rpc_calls16"), "rpc_one_u16", 1, 1);
        requireCallArity(results.get("rpc_calls16"), "rpc_four_s16", 4, 2);
        requireCallArity(results.get("rpc_div_s64"), "__c28xabi_divll", 2, 1);
        requireCallArity(results.get("rpc_div_u64"), "__c28xabi_divull", 2, 1);
        requireCallArity(results.get("rpc_calls64"), "rpc_id_s64", 1, 1);
        requireCallArity(results.get("rpc_calls64"), "rpc_two_s64", 2, 1);
        requireCallArity(results.get("rpc_calls64"), "rpc_mixed_s64", 4, 1);
        requireCallArity(results.get("rpc_calls64"), "rpc_div_s64", 2, 1);
        requireCallArity(results.get("rpc_calls64"), "rpc_div_u64", 2, 1);

        String idText = text.get("rpc_id_s64");
        require(idText.contains("longlong rpc_id_s64(longlong value)") &&
            idText.contains("return value;"),
            "64-bit identity did not remain a joined scalar\n" + idText);
        String twoText = text.get("rpc_two_s64");
        require(twoText.contains("longlong first") && twoText.contains("longlong second"),
            "two-long-long signature not recovered\n" + twoText);
        String signedDivision = text.get("rpc_div_s64");
        String unsignedDivision = text.get("rpc_div_u64");
        require(signedDivision.contains("__c28xabi_divll") &&
            unsignedDivision.contains("__c28xabi_divull"),
            "TI RTS long-long division path not recovered\n" + signedDivision +
                unsignedDivision);

        StringBuilder longLongText = new StringBuilder();
        for (String name : new String[] {
            "rpc_id_s64", "rpc_two_s64", "rpc_mixed_s64", "rpc_div_s64",
            "rpc_div_u64", "rpc_calls64", "rpc_scalar_fixture_entry"
        }) {
            longLongText.append(text.get(name)).append('\n');
        }
        String longLongLower = longLongText.toString().toLowerCase(Locale.ROOT);
        require(!longLongLower.contains("stack[0x1ee]") &&
            !longLongLower.contains("stack0x000001ee") &&
            !longLongLower.contains("return_storage"),
            "64-bit prototype retained hidden-result/high-stack artifacts\n" + longLongText);

        int scalarCompletedCalls = 0;
        for (String name : new String[] {
            "rpc_calls16", "rpc_calls64", "rpc_scalar_fixture_entry",
            "rpc_div_s64", "rpc_div_u64"
        }) {
            scalarCompletedCalls += requireBalancedCompletedCalls(name,
                decompile(function(name), "firstpass"));
        }

        println("RPC_ABI_SCALAR_OPTIMIZATION=" + optimization);
        println("RPC_ABI_SCALAR16_STORAGE=PASS");
        println("RPC_ABI_SCALAR16_CALL_ARITY=PASS");
        println("RPC_ABI_SCALAR16_STALE_AH=0");
        println("RPC_ABI_SCALAR32_STORAGE=PASS");
        println("RPC_ABI_SCALAR64_STORAGE=PASS");
        println("RPC_ABI_SCALAR64_HIGHFUNCTION=PASS");
        println("RPC_ABI_TYPE_PRIORITY_MIXED=PASS");
        println("RPC_ABI_LONG_LONG_HELPERS=PASS");
        println("RPC_ABI_SCALAR_COMPLETED_CALLS=" + scalarCompletedCalls);
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
