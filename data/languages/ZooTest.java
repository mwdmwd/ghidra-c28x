import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.RefType;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/** Structural regressions for the checked-in, compiler-generated CL2000 zoo. */
public class ZooTest extends GhidraScript {
    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }

    private static boolean containsTypeToken(String text, String typeName) {
        return text.matches("(?s).*\\b" + typeName + "\\b.*");
    }

    @Override
    public void run() throws Exception {
        String name = currentProgram.getName().toLowerCase(Locale.ROOT);
        String category;
        if (name.startsWith("switch_saved32_density_boundary_")) {
            testDensityBoundary();
            category = "switch-density-boundary";
        }
        else if (name.startsWith("switch_saved32_")) {
            testRecoveredSwitch(12, 12, "case 0x220:", "case 0x22b:");
            category = "switch-saved32";
        }
        else if (name.startsWith("switch_u16_dense_zero_")) {
            testRecoveredSwitch(12, 12, "case 0:", "case 0xb:");
            category = "switch-u16-dense";
        }
        else if (name.startsWith("switch_u32_holes_shared_")) {
            testHolesAndSharedSwitch();
            category = "switch-holes-shared";
        }
        else if (name.startsWith("switch_s32_cross_zero_")) {
            testRecoveredSwitch(12, 12, "case 0xfffffffa:", "case 5:");
            category = "switch-s32-cross-zero";
        }
        else if (name.startsWith("switch_s16_boundary_")) {
            testRecoverOrCleanReject(1, 12);
            category = "switch-s16-boundary";
        }
        else if (name.startsWith("switch_sequential_nested_")) {
            testRecoverOrCleanReject(2, 12);
            category = "switch-sequential";
        }
        else if (name.startsWith("switch_u16_fallthrough_")) {
            testFallthroughSwitch();
            category = "switch-fallthrough";
        }
        else if (name.startsWith("control_flow_")) {
            testControlFlow();
            category = "control-flow";
        }
        else if (name.startsWith("data_flow_")) {
            testDataFlow();
            category = "data-flow";
        }
        else if (name.startsWith("abi_calls_")) {
            testAbiCalls();
            category = "abi";
        }
        else if (name.startsWith("fpu32_")) {
            testFpu32();
            category = "fpu32";
        }
        else if (name.startsWith("integer_division_")) {
            testIntegerDivision();
            category = "integer-division";
        }
        else if (name.startsWith("tmu_division_")) {
            testTmuDivision();
            category = "tmu-division";
        }
        else if (name.startsWith("tmu_math_")) {
            testTmuMath();
            category = "tmu-math";
        }
        else {
            throw new AssertionError("unrecognized compiler-zoo program " + name);
        }
        println("ZOO_PROGRAM_PASS=" + currentProgram.getName() + " category=" + category);
    }

    private Function entryFunction() {
        AddressIterator entries = currentProgram.getSymbolTable().getExternalEntryPointIterator();
        require(entries.hasNext(), "missing ELF entry point");
        Address entry = entries.next();
        require(!entries.hasNext(), "expected exactly one ELF entry point");
        Function function = getFunctionContaining(entry);
        require(function != null, "missing function containing entry point " + entry);
        return function;
    }

    private List<Instruction> instructions(Function function) {
        List<Instruction> result = new ArrayList<>();
        InstructionIterator iterator =
            currentProgram.getListing().getInstructions(function.getBody(), true);
        while (iterator.hasNext()) {
            result.add(iterator.next());
        }
        return result;
    }

    private int countMnemonic(Function function, String mnemonic) {
        int count = 0;
        for (Instruction instruction : instructions(function)) {
            if (instruction.getMnemonicString().equalsIgnoreCase(mnemonic)) {
                count++;
            }
        }
        return count;
    }

    private List<Instruction> computedBranches(Function function) {
        List<Instruction> result = new ArrayList<>();
        for (Instruction instruction : instructions(function)) {
            if (instruction.getMnemonicString().equalsIgnoreCase("LB") &&
                    instruction.getFlowType().isJump() &&
                    instruction.getFlowType().isComputed()) {
                result.add(instruction);
            }
        }
        return result;
    }

    private List<Address> computedDestinations(Instruction branch) {
        List<Address> result = new ArrayList<>();
        for (Reference reference : currentProgram.getReferenceManager().getReferencesFrom(
                branch.getAddress(), Reference.MNEMONIC)) {
            if (reference.getReferenceType() == RefType.COMPUTED_JUMP) {
                result.add(reference.getToAddress());
            }
        }
        return result;
    }

    private void requireBodyTargets(Function function, List<Address> destinations) {
        for (Address destination : destinations) {
            require(function.getBody().contains(destination),
                "computed destination escaped function body: " + destination);
            MemoryBlock block = currentProgram.getMemory().getBlock(destination);
            require(block != null && block.isExecute(),
                "computed destination is not executable: " + destination);
        }
    }

    private String decompile(Function function) {
        DecompInterface decompiler = new DecompInterface();
        require(decompiler.openProgram(currentProgram), "failed to open decompiler");
        DecompileResults results = decompiler.decompileFunction(function, 30, monitor);
        decompiler.dispose();
        require(results.decompileCompleted(),
            "decompile failed for " + function.getEntryPoint() + ": " +
                results.getErrorMessage());
        return results.getDecompiledFunction().getC();
    }

    private void requireNoIndirectJumpWarning(String c) {
        require(!c.contains("Could not recover jumptable") &&
                !c.contains("Treating indirect jump as call"),
            "unexpected indirect-jump warning\n" + c);
    }

    private int countOccurrences(String text, String needle) {
        int count = 0;
        int offset = 0;
        while ((offset = text.indexOf(needle, offset)) >= 0) {
            count++;
            offset += needle.length();
        }
        return count;
    }

    private void testRecoveredSwitch(int expectedRefs, int expectedCases,
            String firstCase, String lastCase) {
        Function function = entryFunction();
        List<Instruction> branches = computedBranches(function);
        require(branches.size() == 1,
            "expected one computed switch branch, got " + branches.size());
        List<Address> destinations = computedDestinations(branches.get(0));
        require(destinations.size() == expectedRefs,
            "expected " + expectedRefs + " computed refs, got " + destinations.size());
        require(destinations.stream().distinct().count() == expectedRefs,
            "computed destinations are not distinct: " + destinations);
        requireBodyTargets(function, destinations);

        String c = decompile(function);
        requireNoIndirectJumpWarning(c);
        require(countOccurrences(c, "case ") == expectedCases,
            "expected " + expectedCases + " case labels\n" + c);
        require(c.contains(firstCase) && c.contains(lastCase),
            "recovered switch lost boundary labels " + firstCase + " / " + lastCase +
                "\n" + c);
    }

    private void testHolesAndSharedSwitch() {
        Function function = entryFunction();
        List<Instruction> branches = computedBranches(function);
        require(branches.size() == 1, "expected one holes/shared computed branch");
        List<Address> destinations = computedDestinations(branches.get(0));
        require(destinations.size() == 11,
            "expected 11 distinct destinations after sharing/default fill, got " +
                destinations.size());
        require(destinations.stream().distinct().count() == 11,
            "holes/shared destinations unexpectedly repeat");
        requireBodyTargets(function, destinations);

        String c = decompile(function);
        requireNoIndirectJumpWarning(c);
        require(countOccurrences(c, "case ") == 12,
            "holes/shared switch lost explicit labels\n" + c);
        require(c.contains("case 0x100:") && c.contains("case 0x103:") &&
                c.contains("case 0x105:") && c.contains("case 0x108:") &&
                c.contains("case 0x10f:"),
            "holes/shared labels were reconstructed incorrectly\n" + c);
        require(!c.contains("case 0x102:"),
            "default-filled hole 0x102 became a case label\n" + c);
        require(c.contains("default:"), "holes/shared switch lost its default path\n" + c);
    }

    private boolean isCanonical(Address address, Register context) {
        return BigInteger.ONE.equals(
            currentProgram.getProgramContext().getValue(context, address, false));
    }

    /** Accept future conservative support, but require today's unsupported form to reject cleanly. */
    private void testRecoverOrCleanReject(int expectedBranches, int refsWhenRecovered) {
        Function function = entryFunction();
        List<Instruction> branches = computedBranches(function);
        require(branches.size() == expectedBranches,
            "expected " + expectedBranches + " computed branches, got " + branches.size());
        Register context = currentProgram.getProgramContext().getRegister("switch_canonical");
        require(context != null, "missing switch_canonical context");

        int recovered = 0;
        int rejected = 0;
        List<Address> allDestinations = new ArrayList<>();
        for (Instruction branch : branches) {
            List<Address> destinations = computedDestinations(branch);
            if (destinations.isEmpty()) {
                rejected++;
                require(!isCanonical(branch.getAddress(), context),
                    "rejected computed branch was canonicalized at " + branch.getAddress());
            }
            else {
                recovered++;
                require(destinations.size() == refsWhenRecovered,
                    "partially recovered switch at " + branch.getAddress() + " has " +
                        destinations.size() + " refs");
                allDestinations.addAll(destinations);
            }
        }
        require(recovered == expectedBranches || rejected == expectedBranches,
            "switch family was only partially recovered: recovered=" + recovered +
                " rejected=" + rejected);

        String c = decompile(function);
        if (recovered == expectedBranches) {
            requireBodyTargets(function, allDestinations);
            requireNoIndirectJumpWarning(c);
        }
        else {
            require(c.contains("Could not recover jumptable") &&
                    c.contains("Treating indirect jump as call"),
                "cleanly rejected switch lacks the expected stock-Ghidra classification\n" + c);
        }
    }

    private void testDensityBoundary() {
        Function function = entryFunction();
        require(computedBranches(function).isEmpty(),
            "eleven-case density boundary unexpectedly used a jump table");
        require(countMnemonic(function, "PREAD") == 0,
            "density boundary unexpectedly contains PREAD");
        require(countMnemonic(function, "CMPL") >= 1,
            "density boundary lost its comparison tree");
        String c = decompile(function);
        requireNoIndirectJumpWarning(c);
        require(c.contains("0x220") && c.contains("0x22a"),
            "density-boundary comparison tree lost selector limits\n" + c);
    }

    private void testFallthroughSwitch() {
        Function function = entryFunction();
        require(computedBranches(function).isEmpty(),
            "fallthrough family unexpectedly used a jump table");
        require(countMnemonic(function, "PREAD") == 0,
            "fallthrough family unexpectedly contains PREAD");
        String c = decompile(function);
        requireNoIndirectJumpWarning(c);
        require(c.contains("return 7;") && c.contains("return -1;") &&
                c.contains("return 0xb;") && c.contains("param_1[7]") &&
                c.contains("param_1[1]"),
            "fallthrough/default/multi-exit behavior was not preserved\n" + c);
        require(c.contains("+ 2") && c.contains("+ 6"),
            "fallthrough accumulation was not preserved\n" + c);
    }

    private boolean hasBackEdge(Function function) {
        for (Instruction instruction : instructions(function)) {
            if (!instruction.getFlowType().isJump()) {
                continue;
            }
            for (Address flow : instruction.getFlows()) {
                if (function.getBody().contains(flow) &&
                        flow.compareTo(instruction.getAddress()) < 0) {
                    return true;
                }
            }
        }
        return false;
    }

    private String normalizedInstruction(Instruction instruction) {
        return instruction.toString().toUpperCase(Locale.ROOT)
            .replaceAll("\\s+", "")
            .replace("@", "");
    }

    private Instruction findRegisterMove(Function function, String destination, String source) {
        String expected = "MOVL" + destination.toUpperCase(Locale.ROOT) + "," +
            source.toUpperCase(Locale.ROOT);
        for (Instruction instruction : instructions(function)) {
            if (normalizedInstruction(instruction).equals(expected)) {
                return instruction;
            }
            if (!instruction.getMnemonicString().equalsIgnoreCase("MOVL") ||
                    instruction.getNumOperands() < 2) {
                continue;
            }
            Register destinationRegister = instruction.getRegister(0);
            Register sourceRegister = instruction.getRegister(1);
            if (destinationRegister != null && sourceRegister != null &&
                    destinationRegister.getName().equalsIgnoreCase(destination) &&
                    sourceRegister.getName().equalsIgnoreCase(source)) {
                return instruction;
            }
        }
        throw new AssertionError("missing MOVL " + destination + "," + source);
    }

    private String varnodeKey(Varnode node) {
        return node.getAddress().getAddressSpace().getName() + ":" +
            node.getOffset() + ":" + node.getSize();
    }

    private String registerName(Varnode node) {
        if (node == null || !node.getAddress().isRegisterAddress()) {
            return null;
        }
        Register register = currentProgram.getLanguage().getRegister(
            node.getAddress(), node.getSize());
        return register == null ? null : register.getName();
    }

    private boolean dependsOnRegister(PcodeOp[] ops, Varnode node, String registerName) {
        Map<String, PcodeOp> definitions = new HashMap<>();
        for (PcodeOp op : ops) {
            if (op.getOutput() != null && op.getOutput().isUnique()) {
                definitions.put(varnodeKey(op.getOutput()), op);
            }
        }
        Set<String> seen = new HashSet<>();
        return dependsOnRegister(definitions, seen, node, registerName);
    }

    private boolean dependsOnRegister(Map<String, PcodeOp> definitions, Set<String> seen,
            Varnode node, String expected) {
        String actual = registerName(node);
        if (actual != null && actual.equalsIgnoreCase(expected)) {
            return true;
        }
        if (node == null || !node.isUnique()) {
            return false;
        }
        String key = varnodeKey(node);
        if (!seen.add(key)) {
            return false;
        }
        PcodeOp definition = definitions.get(key);
        if (definition == null) {
            return false;
        }
        for (Varnode input : definition.getInputs()) {
            if (dependsOnRegister(definitions, seen, input, expected)) {
                return true;
            }
        }
        return false;
    }

    private void requireMovlAccFlags(Instruction instruction) {
        PcodeOp[] pcode = instruction.getPcode();
        int accWrite = -1;
        int nWrite = -1;
        int zWrite = -1;
        PcodeOp nOperation = null;
        PcodeOp zOperation = null;
        for (int index = 0; index < pcode.length; index++) {
            String output = registerName(pcode[index].getOutput());
            if ("ACC".equalsIgnoreCase(output)) {
                accWrite = index;
            }
            else if ("N".equalsIgnoreCase(output)) {
                nWrite = index;
                nOperation = pcode[index];
            }
            else if ("Z".equalsIgnoreCase(output)) {
                zWrite = index;
                zOperation = pcode[index];
            }
        }
        require(accWrite >= 0 && nWrite > accWrite && zWrite > accWrite,
            "MOVL-to-ACC does not update ACC before N/Z: " + instruction);
        require(nOperation != null && nOperation.getNumInputs() > 0 &&
                dependsOnRegister(pcode, nOperation.getInput(0), "ACC"),
            "MOVL-to-ACC N flag does not depend on ACC: " + instruction);
        require(zOperation != null && zOperation.getNumInputs() > 0 &&
                dependsOnRegister(pcode, zOperation.getInput(0), "ACC"),
            "MOVL-to-ACC Z flag does not depend on ACC: " + instruction);
    }

    private void testControlFlow() {
        Function function = entryFunction();
        require(countMnemonic(function, "CMPL") >= 1,
            "control-flow probe lost its 32-bit compare");
        require(countMnemonic(function, "TBIT") >= 1,
            "control-flow probe lost boolean materialization");
        require(hasBackEdge(function), "control-flow probe lost its loop back edge");

        Instruction pointerTest = findRegisterMove(function, "ACC", "XAR4");
        Instruction signedTest = findRegisterMove(function, "ACC", "P");
        requireMovlAccFlags(pointerTest);
        requireMovlAccFlags(signedTest);

        String c = decompile(function);
        requireNoIndirectJumpWarning(c);
        require(!c.contains("in_Z"),
            "decompiler consumed stale incoming Z after MOVL-to-ACC\n" + c);
        require(!containsTypeToken(c, "int5") && !containsTypeToken(c, "uint3"),
            "common compare arithmetic exposed a nonstandard-width type\n" + c);
        require(c.contains("param_1 == 0") && c.contains("0x55aa"),
            "null check or reverse-loop sentinel was lost\n" + c);
        require(c.contains("while") || c.contains("for ("),
            "control-flow loops were not reconstructed\n" + c);
    }

    private void testDataFlow() {
        Function function = entryFunction();
        require(countMnemonic(function, "MOVB") >= 2, "missing byte load/store family");
        require(countMnemonic(function, "ADDUL") >= 1, "missing unsigned low-word add");
        require(countMnemonic(function, "ADDCL") >= 1, "missing carry-chain add");
        require(countMnemonic(function, "SUBUL") >= 1, "missing unsigned low-word subtract");
        require(countMnemonic(function, "SUBBL") >= 1, "missing borrow-chain subtract");

        String c = decompile(function);
        requireNoIndirectJumpWarning(c);
        require(!containsTypeToken(c, "int5") && !containsTypeToken(c, "uint3"),
            "common carry/borrow arithmetic exposed a nonstandard-width type\n" + c);
        require(c.contains(">> 1") && c.contains("0xff") &&
                c.contains("0x100000000"),
            "byte-index scaling/masking or 64-bit carry boundary was lost\n" + c);
    }

    private void testAbiCalls() {
        Function entry = entryFunction();
        List<Function> functions = new ArrayList<>();
        FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true);
        while (iterator.hasNext()) {
            functions.add(iterator.next());
        }
        require(functions.size() == 2,
            "ABI fixture should contain entry and helper functions, got " + functions.size());
        Function helper = functions.get(0).equals(entry) ? functions.get(1) : functions.get(0);

        Instruction call = null;
        boolean stackAllocation = false;
        boolean stackRelease = false;
        for (Instruction instruction : instructions(entry)) {
            if (instruction.getFlowType().isCall() &&
                    instruction.getMnemonicString().equalsIgnoreCase("LCR")) {
                require(call == null, "expected one direct LCR call");
                call = instruction;
            }
            String normalized = normalizedInstruction(instruction);
            if (normalized.startsWith("ADDBSP,")) {
                stackAllocation = true;
            }
            if (normalized.startsWith("SUBBSP,")) {
                stackRelease = true;
            }
        }
        require(call != null, "ABI fixture lost direct LCR call");
        Address[] callFlows = call.getFlows();
        require(callFlows.length == 1 && callFlows[0].equals(helper.getEntryPoint()),
            "direct call does not target the helper function");
        require(stackAllocation && stackRelease,
            "ABI fixture lost stack allocation/release");
        require(countMnemonic(entry, "LRETR") >= 1 &&
                countMnemonic(helper, "LRETR") >= 1,
            "ABI functions lost architectural returns");
        require(entry.getBody().contains(call.getAddress()),
            "direct call escaped entry function body");

        String entryC = decompile(entry);
        String helperC = decompile(helper);
        requireNoIndirectJumpWarning(entryC);
        requireNoIndirectJumpWarning(helperC);
        require(entryC.contains("FUN_00018000("),
            "entry decompilation lost helper call\n" + entryC);
        require(helperC.contains("0x55aa") && helperC.contains("0x1234"),
            "helper structure/constants were not preserved\n" + helperC);
    }

    private void testFpu32() {
        Function function = entryFunction();
        require(countMnemonic(function, "MPYF32") >= 1, "missing FPU multiply");
        require(countMnemonic(function, "ADDF32") >= 1, "missing FPU add");
        require(countMnemonic(function, "CMPF32") >= 1, "missing FPU compare");
        require(countMnemonic(function, "MOVST0") >= 1, "missing STF-to-ST0 transfer");
        require(countMnemonic(function, "F32TOUI16") >= 1,
            "missing FPU-to-unsigned conversion");
        require(hasBackEdge(function), "FPU probe lost its bounded loop");

        String c = decompile(function);
        requireNoIndirectJumpWarning(c);
        require(c.contains("65535.0") && c.contains("0xffff") && c.contains("0.5"),
            "FPU range, conversion, or fused source expression was lost\n" + c);
    }

    private void testIntegerDivision() {
        Function function = entryFunction();
        require(countMnemonic(function, "RPT") == 3,
            "integer-division probe lost its three repeat schedules");
        require(countMnemonic(function, "SUBCUL") == 2,
            "integer-division probe lost 32-bit quotient/remainder schedules");
        require(countMnemonic(function, "SUBCU") == 1,
            "integer-division probe lost its 16-bit quotient schedule");

        String c = decompile(function);
        requireNoIndirectJumpWarning(c);
        require(!c.contains("uint5") && !c.contains("0x100000000"),
            "SUBCU(L) leaked the eliminated five-byte temporary into C\n" + c);
    }

    private Instruction singleMnemonic(Function function, String mnemonic) {
        Instruction result = null;
        for (Instruction instruction : instructions(function)) {
            if (!instruction.getMnemonicString().equalsIgnoreCase(mnemonic)) {
                continue;
            }
            require(result == null, "expected exactly one " + mnemonic);
            result = instruction;
        }
        require(result != null, "missing " + mnemonic);
        return result;
    }

    private boolean pcodeReadsRegister(Instruction instruction, String expected) {
        PcodeOp[] pcode = instruction.getPcode();
        for (PcodeOp op : pcode) {
            for (Varnode input : op.getInputs()) {
                if (dependsOnRegister(pcode, input, expected)) {
                    return true;
                }
            }
        }
        return false;
    }

    private boolean pcodeWritesRegister(Instruction instruction, String expected) {
        for (PcodeOp op : instruction.getPcode()) {
            String output = registerName(op.getOutput());
            if (output != null && output.equalsIgnoreCase(expected)) {
                return true;
            }
        }
        return false;
    }

    private void requireTmuDelaySlotSafe(Instruction producer, int count,
            String destination) {
        Instruction slot = producer;
        String[] destructiveFlags = {
            "STF_TF", "STF_ZI", "STF_NI", "STF_ZF", "STF_NF", "STF_LU", "STF_LV"
        };
        for (int index = 0; index < count; index++) {
            slot = currentProgram.getListing().getInstructionAfter(slot.getAddress());
            require(slot != null,
                producer.getMnemonicString() + " lost delay slot " + (index + 1));
            require(!slot.getFlowType().isJump() && !slot.getFlowType().isCall() &&
                    !slot.getFlowType().isTerminal(),
                producer.getMnemonicString() + " gained control flow in delay slot: " + slot);
            require(!pcodeReadsRegister(slot, destination) &&
                    !pcodeWritesRegister(slot, destination),
                producer.getMnemonicString() + " destination is observed/clobbered early by " +
                    slot);
            for (String flag : destructiveFlags) {
                // Sticky TMU producers may write LUF/LVF in an overlapping safe
                // schedule, but no delay-slot instruction may observe any STF
                // flag.  The eventual-state model deliberately does not claim
                // cycle-accurate publication for such overlap.
                require(!pcodeReadsRegister(slot, flag),
                    producer.getMnemonicString() + " flag is observed in delay slot by " + slot);
            }
        }
    }

    /** Compiler integration regression for SQRTF32/DIV2PIF32/COSPUF32. */
    private void testTmuMath() {
        Function function = entryFunction();
        Instruction root = singleMnemonic(function, "SQRTF32");
        Instruction scale = singleMnemonic(function, "DIV2PIF32");
        Instruction cosine = singleMnemonic(function, "COSPUF32");
        require(function.getBody().contains(root.getAddress()) &&
                function.getBody().contains(scale.getAddress()) &&
                function.getBody().contains(cosine.getAddress()),
            "TMU math instructions escaped the entry function body");

        Register rootDestination = root.getRegister(0);
        Register scaleDestination = scale.getRegister(0);
        Register cosineDestination = cosine.getRegister(0);
        require(rootDestination != null && scaleDestination != null &&
                cosineDestination != null,
            "TMU math operands did not decode as registers");

        // SQRTF32 is 5p and COSPUF32 is 4p.  These checks prove that the
        // compiler's intervening instructions neither observe nor overwrite
        // the pending destination and do not branch/call/return or read STF.
        requireTmuDelaySlotSafe(root, 4, rootDestination.getName());
        requireTmuDelaySlotSafe(cosine, 3, cosineDestination.getName());

        // DIV2PIF32 is 2p when feeding SINPUF32/COSPUF32 and otherwise 3p.
        // Locate the consuming cosine and prove every intervening operation is
        // non-observing.  O0 uses one NOP; O2 safely interleaves SQRTF32 plus a
        // NOP and therefore uses the ordinary 3p path.
        Instruction cursor = scale;
        int intervening = 0;
        while (true) {
            cursor = currentProgram.getListing().getInstructionAfter(cursor.getAddress());
            require(cursor != null && intervening <= 2,
                "DIV2PIF32 did not feed the bounded COSPUF32 schedule");
            if (cursor.equals(cosine)) {
                break;
            }
            require(!pcodeReadsRegister(cursor, scaleDestination.getName()) &&
                    !pcodeWritesRegister(cursor, scaleDestination.getName()),
                "DIV2PIF32 result is observed/clobbered before COSPUF32: " + cursor);
            require(!cursor.getFlowType().isJump() && !cursor.getFlowType().isCall() &&
                    !cursor.getFlowType().isTerminal(),
                "DIV2PIF32 gained control flow before COSPUF32: " + cursor);
            intervening++;
        }
        require(intervening == 1 || intervening == 2,
            "unexpected DIV2PIF32/COSPUF32 distance: " + intervening);
        Register cosineSource = cosine.getRegister(1);
        require(cosineSource != null &&
                cosineSource.getName().equalsIgnoreCase(scaleDestination.getName()),
            "COSPUF32 no longer consumes the DIV2PIF32 result");

        String c = decompile(function);
        requireNoIndirectJumpWarning(c);
        require(!c.contains("bad instruction data") &&
                !c.contains("UNIMPLEMENTED"),
            "TMU math schedule still breaks decompilation\n" + c);
    }

    /** Compiler integration regression for the ordinary TMU0 division schedule. */
    private void testTmuDivision() {
        Function function = entryFunction();
        List<Instruction> divisions = new ArrayList<>();
        for (Instruction instruction : instructions(function)) {
            if (instruction.getMnemonicString().equalsIgnoreCase("DIVF32")) {
                divisions.add(instruction);
            }
        }
        require(divisions.size() == 1,
            "TMU division probe must contain exactly one DIVF32");
        Instruction division = divisions.get(0);
        require(function.getBody().contains(division.getAddress()),
            "decoded DIVF32 is missing from the entry function body");

        // DIVF32 publishes its result and LVF/LUF updates on cycle five.  The
        // instruction-level P-Code collapse is observationally safe for these
        // compiler fixtures only because the four intervening instructions do
        // not read the result or the TMU flags.
        Instruction slot = division;
        for (int index = 0; index < 4; index++) {
            slot = currentProgram.getListing().getInstructionAfter(slot.getAddress());
            require(slot != null, "TMU division probe lost delay slot " + (index + 1));
            String mnemonic = slot.getMnemonicString().toUpperCase();
            require(mnemonic.equals("NOP") || mnemonic.equals("MOVB"),
                "TMU division probe gained an observable delay-slot operation: " + slot);
        }

        String c = decompile(function);
        require(!c.contains("bad instruction data") &&
                !c.contains("UNIMPLEMENTED"),
            "decoded DIVF32 still breaks decompilation\n" + c);
    }
}
