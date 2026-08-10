import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.RefType;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class SwitchTest extends GhidraScript {
    private static final long VALID_FUNCTION = 0x13015;
    private static final long VALID_INDEX = 0x1301d;
    private static final long VALID_BRANCH = 0x13024;
    private static final long SAVED_FUNCTION = 0x13092;
    private static final long SAVED_BRANCH0 = 0x130aa;
    private static final long SAVED_BRANCH1 = 0x130b4;
    private static final long SAVED_P_FUNCTION = 0x130c9;
    private static final long SAVED_P_BRANCH = 0x130d8;
    private static final long SAVED_HI_FUNCTION = 0x1310a;
    private static final long SAVED_HI_BRANCH = 0x13119;

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }

    @Override
    public void run() throws Exception {
        String name = currentProgram.getName().toLowerCase();
        if (name.contains("ffc_validation")) {
            testFfcValidationFixture();
            println("SWITCH_PROGRAM_PASS=" + currentProgram.getName());
            return;
        }
        if (name.contains("ar6_validation")) {
            testAr6ValidationFixture();
        }
        else if (name.contains("pread_validation")) {
            testPreadNegativeFixture();
        }
        else if (name.contains("validation")) {
            testCompactValidationFixture();
        }
        else if (name.contains("pread32")) {
            testPread32CompilerFixture();
        }
        else {
            testCompilerFixture();
        }
        requireNoFfcReturnContext();
        println("SWITCH_PROGRAM_PASS=" + currentProgram.getName());
    }

    private void testFfcValidationFixture() throws Exception {
        Register ffcContext = currentProgram.getProgramContext().getRegister("ffc_return");
        Register switchContext =
            currentProgram.getProgramContext().getRegister("switch_canonical");
        require(ffcContext != null, "missing ffc_return context");
        require(switchContext != null, "missing switch_canonical context");

        Address validReturn = wordAddress(0x16025);
        Instruction valid = getInstructionAt(validReturn);
        require(valid != null && valid.getMnemonicString().equalsIgnoreCase("LB"),
            "missing positive FFC-return LB");
        require(isCanonical(validReturn, ffcContext),
            "positive FFC helper return was not tagged");
        require(!isCanonical(validReturn, switchContext),
            "FFC helper return was incorrectly tagged as a switch");
        require(valid.getFlowType().isTerminal() && !valid.getFlowType().isCall(),
            "positive FFC LB is not a return terminator: " + valid.getFlowType());
        require(hasPcodeOp(valid, PcodeOp.RETURN) &&
                !hasPcodeOp(valid, PcodeOp.BRANCHIND) &&
                !hasPcodeOp(valid, PcodeOp.CALLIND),
            "positive FFC LB did not select RETURNIND P-Code");

        int tagged = 0;
        InstructionIterator instructions = currentProgram.getListing().getInstructions(true);
        while (instructions.hasNext()) {
            if (isCanonical(instructions.next().getAddress(), ffcContext)) {
                tagged++;
            }
        }
        require(tagged == 1, "only the proven FFC terminal may be tagged, got " + tagged);

        long[] rejectedReturns = {
            0x16028, // XAR7 clobber
            0x1602a, // mixed FFC/LCR ingress
            0x1602d, // external ingress into helper interior
            0x16030, // explicit control flow in helper
            0x16033, // fall-through into nominal helper entry
            0x16036  // ordinary indirect branch with no FFC provenance
        };
        for (long word : rejectedReturns) {
            Address address = wordAddress(word);
            Instruction instruction = getInstructionAt(address);
            require(instruction != null && instruction.getMnemonicString().equalsIgnoreCase("LB"),
                "missing FFC near-miss LB at " + address);
            require(!isCanonical(address, ffcContext),
                "FFC near miss was tagged at " + address);
            require(hasPcodeOp(instruction, PcodeOp.BRANCHIND) &&
                    !hasPcodeOp(instruction, PcodeOp.RETURN),
                "untagged LB lost ordinary BRANCHIND P-Code at " + address);
        }

        Instruction clobber = getInstructionAt(wordAddress(0x16026));
        require(clobber != null && isRegisterOperand(clobber, 0, "XAR7"),
            "XAR7-clobber near miss no longer writes XAR7");
        require(hasCallReferenceFromMnemonic(0x16029, "FFC") &&
                hasCallReferenceFromMnemonic(0x16029, "LCR"),
            "mixed-ingress near miss no longer has both FFC and LCR callers");
        require(hasFlowReferenceFromTo(0x1602e, 0x1602c),
            "external-ingress near miss lost its interior branch");
        Instruction explicitFlow = getInstructionAt(wordAddress(0x1602f));
        require(explicitFlow != null && explicitFlow.getMnemonicString().equalsIgnoreCase("SB") &&
                explicitFlow.getFlowType().isJump(),
            "control-flow near miss no longer branches before its LB");
        Instruction fallthrough = getInstructionAt(wordAddress(0x16031));
        require(fallthrough != null && wordAddress(0x16032).equals(fallthrough.getFallThrough()),
            "fall-through near miss no longer enters the nominal helper");
        require(hasCallReferenceFromMnemonic(0x16034, "LCR") &&
                !hasCallReferenceFromMnemonic(0x16034, "FFC"),
            "ordinary indirect branch no longer has only non-FFC provenance");

        require(hasFlowReferenceFromTo(0x16000, 0x16017) &&
                hasFlowReferenceFromTo(0x16002, 0x16017),
            "positive helper lost one of its two FFC callers");
        Function helper = getFunctionAt(wordAddress(0x16017));
        require(helper != null, "missing positive FFC helper function");
        require("__ffc".equals(helper.getCallingConventionName()),
            "positive FFC helper did not select __ffc: " +
                helper.getCallingConventionName());
        require(helper.getBody().contains(wordAddress(0x16017)) &&
                helper.getBody().contains(validReturn),
            "positive FFC helper body does not include its terminal return");
        int helperInstructions = 0;
        InstructionIterator helperBody =
            currentProgram.getListing().getInstructions(helper.getBody(), true);
        while (helperBody.hasNext()) {
            helperBody.next();
            helperInstructions++;
        }
        require(helperInstructions == 14,
            "positive FFC helper instruction count changed: " + helperInstructions);

        String c = decompile(helper);
        require(!c.contains("Could not recover jumptable") &&
                !c.contains("Treating indirect jump as call") &&
                c.contains("return "),
            "FFC helper did not decompile as a returning function\n" + c);

        println("FFC_RETURN_CALLERS=2");
        println("FFC_RETURN_HELPER_INSTRUCTIONS=14");
        println("FFC_RETURN_NEAR_MISS_REJECTED=6");
        println("FFC_RETURN_CALLING_CONVENTION=__ffc");
    }

    private void testAr6ValidationFixture() throws Exception {
        Register context = currentProgram.getProgramContext().getRegister("switch_canonical");
        require(context != null, "missing switch_canonical context");

        Address validAdd = wordAddress(0x15027);
        Address validBranch = wordAddress(0x1502b);
        require(isCanonical(validAdd, context),
            "AR6 positive fixture index ADD was not canonicalized");
        require(isCanonical(validBranch, context),
            "AR6 positive fixture computed LB was not canonicalized");
        require(computedJumpCount(validBranch) == 3,
            "AR6 positive fixture must recover three destinations");

        int canonicalCount = 0;
        InstructionIterator all = currentProgram.getListing().getInstructions(true);
        while (all.hasNext()) {
            Instruction instruction = all.next();
            if (isCanonical(instruction.getAddress(), context)) {
                canonicalCount++;
            }
        }
        require(canonicalCount == 2,
            "only the positive AR6 ADD/LB may be canonical, got " + canonicalCount);

        long[] rejectedBranches = {
            0x15040, 0x15055, 0x1506a, 0x1507f, 0x15090, 0x150a4, 0x150b9,
            0x150ce, 0x150e3, 0x150f8, 0x1510e, 0x15123, 0x15138
        };
        for (long branch : rejectedBranches) {
            require(!isCanonical(wordAddress(branch), context),
                "AR6 near miss was canonicalized at " + wordAddress(branch));
        }

        // One minimized negative isolates each newly admitted matcher fact.
        require(getInstructionAt(wordAddress(0x15034)).getMnemonicString()
                .equalsIgnoreCase("MOV"),
            "producer near miss no longer uses MOV instead of MOVZ");
        require(isRegisterOperand(getInstructionAt(wordAddress(0x1504a)), 1, "AR5"),
            "selector-copy near miss no longer reads AR5");
        require(isRegisterOperand(getInstructionAt(wordAddress(0x15060)), 0, "AH"),
            "compare-register near miss no longer compares AH");
        require(scalarAt(0x15075, 1) == 0,
            "count-bound near miss no longer describes one entry");
        require(getInstructionAt(wordAddress(0x15087))
                .getDefaultOperandRepresentation(1).equalsIgnoreCase("GEQ"),
            "guard-condition near miss no longer uses GEQ");
        require(isRegisterOperand(getInstructionAt(wordAddress(0x1509d)), 1, "XAR4"),
            "table-base near miss no longer uses a register pointer");
        require(getInstructionAt(wordAddress(0x150b3)).getMnemonicString()
                .equalsIgnoreCase("CLRC"),
            "SXM near miss no longer clears SXM");
        require(isRegisterOperand(getInstructionAt(wordAddress(0x150c9)), 1, "XAR6"),
            "base-copy near miss no longer reads XAR6");
        require(isRegisterOperand(getInstructionAt(wordAddress(0x150df)), 1, "AR5"),
            "index-source near miss no longer reads AR5");
        require(scalarAt(0x150f4, 2) == 2,
            "index-scale near miss no longer shifts by two");
        Instruction copyBack = getInstructionAt(wordAddress(0x1510b));
        Instruction copyRoute = getInstructionAt(wordAddress(0x1510c));
        require(isRegisterMove(copyBack, "MOVL", "XAR6", "ACC") &&
                copyRoute != null &&
                copyRoute.getMnemonicString().equalsIgnoreCase("MOVL") &&
                !isRegisterMove(copyBack, "MOVL", "XAR7", "ACC"),
            "copy-back near miss no longer routes through XAR6");
        Instruction offsetLoad = getInstructionAt(wordAddress(0x15122));
        Object[] offsetObjects = offsetLoad == null ? new Object[0] : offsetLoad.getOpObjects(1);
        require(offsetObjects.length == 2 && offsetObjects[1] instanceof Scalar offset &&
                offset.getUnsignedValue() == 2,
            "native-load near miss no longer uses offset two");
        require(hasFlowReferenceFromTo(0x15141, 0x15134),
            "exclusive-ingress near miss lost its branch into the dispatch");

        Function function = getFunctionAt(wordAddress(0x1501f));
        require(function != null, "missing AR6 positive fixture function");
        long[] targets = { 0x1502e, 0x15030, 0x15032 };
        for (long target : targets) {
            require(function.getBody().contains(wordAddress(target)),
                "AR6 switch target not in recovered function body: " + wordAddress(target));
        }
        String c = decompile(function);
        require(!c.contains("Could not recover jumptable") &&
                !c.contains("Treating indirect jump as call"),
            "AR6 switch remains unrecovered\n" + c);
        require(c.contains("case 0:") && c.contains("case 2:"),
            "AR6 switch lost its zero-based case range\n" + c);

        println("SWITCH_AR6_DESTINATIONS=3");
        println("SWITCH_AR6_CASE_RANGE=0-2");
        println("SWITCH_AR6_NEAR_MISS_REJECTED=13");
    }

    private void testPread32CompilerFixture() throws Exception {
        AddressIterator entryPoints =
            currentProgram.getSymbolTable().getExternalEntryPointIterator();
        require(entryPoints.hasNext(), "expected an ELF entry point");
        Address entryPoint = entryPoints.next();
        Function function = getFunctionAt(entryPoint);
        require(function != null, "expected a function at ELF entry point " + entryPoint);

        Register context = currentProgram.getProgramContext().getRegister("switch_canonical");
        require(context != null, "missing switch_canonical context");

        int preadCount = 0;
        int computedBranches = 0;
        int canonicalSubs = 0;
        int canonicalBranches = 0;
        int canonicalLsls = 0;
        Instruction guard = null;
        Instruction branch = null;
        List<Address> destinations = new ArrayList<>();

        InstructionIterator instructions =
            currentProgram.getListing().getInstructions(function.getBody(), true);
        while (instructions.hasNext()) {
            Instruction instruction = instructions.next();
            String mnemonic = instruction.getMnemonicString();
            boolean canonical = isCanonical(instruction.getAddress(), context);
            if (mnemonic.equalsIgnoreCase("PREAD")) {
                preadCount++;
            }
            if (mnemonic.equalsIgnoreCase("SUB") && canonical) {
                canonicalSubs++;
            }
            if (mnemonic.equalsIgnoreCase("LSL") && canonical) {
                canonicalLsls++;
            }
            if (isUnsignedHiGuard(instruction)) {
                require(guard == null, "expected exactly one HI guard");
                guard = instruction;
            }
            if (mnemonic.equalsIgnoreCase("LB") && instruction.getFlowType().isJump() &&
                    instruction.getFlowType().isComputed()) {
                computedBranches++;
                require(branch == null, "expected exactly one computed LB");
                branch = instruction;
                if (canonical) {
                    canonicalBranches++;
                }
                destinations.addAll(computedJumpDestinations(instruction.getAddress()));
            }
        }

        require(preadCount == 2, "expected exactly two PREAD instructions, got " + preadCount);
        require(computedBranches == 1, "expected one computed LB, got " + computedBranches);
        require(destinations.size() == 12,
            "expected 12 switch destinations, got " + destinations.size());
        require(destinations.stream().distinct().count() == 12,
            "expected 12 distinct switch destinations, got " + destinations);
        Memory memory = currentProgram.getMemory();
        for (Address destination : destinations) {
            require(function.getBody().contains(destination),
                "switch destination is outside the recovered function body: " + destination);
            MemoryBlock block = memory.getBlock(destination);
            require(block != null && block.isExecute(),
                "switch destination is not in executable memory: " + destination);
        }

        require(guard != null, "missing saved-selector HI guard");
        require(guard.getFallThrough() != null &&
                function.getBody().contains(guard.getFallThrough()),
            "HI guard fallthrough is not in the switch function body");
        Address[] guardFlows = guard.getFlows();
        require(guardFlows.length == 1 && function.getBody().contains(guardFlows[0]),
            "HI guard default flow is not in the switch function body");
        require(branch != null && function.getBody().contains(branch.getAddress()),
            "computed branch is outside the function body");

        require(canonicalSubs == 2,
            "expected guard and dispatch SUB canonicalization, got " + canonicalSubs);
        require(canonicalBranches == 1,
            "expected the computed LB to be canonicalized once, got " + canonicalBranches);
        require(canonicalLsls == 0,
            "saved-selector LSL should retain its ordinary semantics");

        String c = decompile(function);
        require(!c.contains("Could not recover jumptable") &&
                !c.contains("Treating indirect jump as call"),
            "saved-selector PREAD switch remains unrecovered\n" + c);
        require(c.contains("case 0x220:") && c.contains("case 0x22b:"),
            "saved-selector PREAD switch lost its original case range\n" + c);

        println("SWITCH_PREAD32_DESTINATIONS=12");
        println("SWITCH_PREAD32_CASE_RANGE=0x220-0x22b");
        println("SWITCH_PREAD32_CANONICAL_SUBS=2");
    }

    private void testPreadNegativeFixture() {
        Register context = currentProgram.getProgramContext().getRegister("switch_canonical");
        require(context != null, "missing switch_canonical context");

        int preadCount = 0;
        int canonicalCount = 0;
        int stockInvalidReferences = 0;
        int incrementByTwo = 0;
        int swappedHalves = 0;
        List<Instruction> branches = new ArrayList<>();

        InstructionIterator instructions = currentProgram.getListing().getInstructions(true);
        while (instructions.hasNext()) {
            Instruction instruction = instructions.next();
            if (instruction.getMnemonicString().equalsIgnoreCase("PREAD")) {
                preadCount++;
            }
            if (isCanonical(instruction.getAddress(), context)) {
                canonicalCount++;
            }
            if (instruction.getMnemonicString().equalsIgnoreCase("LB") &&
                    instruction.getFlowType().isJump() &&
                    instruction.getFlowType().isComputed()) {
                branches.add(instruction);
            }
        }

        require(preadCount == 4, "negative fixture must contain four PREADs, got " + preadCount);
        require(branches.size() == 2,
            "negative fixture must contain two computed LBs, got " + branches.size());
        require(canonicalCount == 0,
            "near-miss PREAD schedules must not be canonicalized, got " + canonicalCount);

        Memory memory = currentProgram.getMemory();
        for (Instruction branch : branches) {
            Instruction finalCopy = contiguousPrevious(branch);
            Instruction secondRead = contiguousPrevious(finalCopy);
            Instruction increment = contiguousPrevious(secondRead);
            Instruction firstRead = contiguousPrevious(increment);
            require(finalCopy != null && secondRead != null && increment != null &&
                    firstRead != null,
                "truncated negative PREAD dispatch before " + branch.getAddress());

            long incrementValue = scalarUnsigned(increment, 1);
            if (isRegisterMove(firstRead, "PREAD", "AL", "XAR7") &&
                    incrementValue == 2 &&
                    isRegisterMove(secondRead, "PREAD", "AH", "XAR7")) {
                incrementByTwo++;
            }
            if (isRegisterMove(firstRead, "PREAD", "AH", "XAR7") &&
                    incrementValue == 1 &&
                    isRegisterMove(secondRead, "PREAD", "AL", "XAR7")) {
                swappedHalves++;
            }

            for (Address destination : computedJumpDestinations(branch.getAddress())) {
                MemoryBlock block = memory.getBlock(destination);
                require(block == null || !block.isExecute(),
                    "stock analysis fabricated an executable target for a rejected schedule: " +
                        destination);
                stockInvalidReferences++;
            }
        }

        require(incrementByTwo == 1,
            "negative fixture lost its increment-by-two PREAD near miss");
        require(swappedHalves == 1,
            "negative fixture lost its swapped-half PREAD near miss");

        println("SWITCH_PREAD_NEGATIVE_REJECTED=2");
        println("SWITCH_PREAD_NEGATIVE_STOCK_INVALID_REFS=" + stockInvalidReferences);
    }

    private void testCompilerFixture() throws Exception {
        AddressIterator entryPoints =
            currentProgram.getSymbolTable().getExternalEntryPointIterator();
        require(entryPoints.hasNext(), "expected an ELF entry point");
        Address entryPoint = entryPoints.next();
        Function function = getFunctionAt(entryPoint);
        require(function != null, "expected a function at ELF entry point " + entryPoint);

        ReferenceManager references = currentProgram.getReferenceManager();
        List<Integer> destinationCounts = new ArrayList<>();
        List<Address> destinations = new ArrayList<>();
        int preadCount = 0;
        int nativeLoadCount = 0;

        InstructionIterator instructions = currentProgram.getListing().getInstructions(true);
        while (instructions.hasNext()) {
            Instruction instruction = instructions.next();
            String mnemonic = instruction.getMnemonicString();
            if (mnemonic.equalsIgnoreCase("PREAD")) {
                preadCount++;
            }
            if (mnemonic.equalsIgnoreCase("MOVL") && instruction.getNumOperands() == 2 &&
                    instruction.getDefaultOperandRepresentation(1)
                        .toUpperCase()
                        .contains("XAR7") &&
                    instruction.getDefaultOperandRepresentation(1).startsWith("*")) {
                nativeLoadCount++;
            }

            if (!mnemonic.equalsIgnoreCase("LB") ||
                    !instruction.getFlowType().isJump() ||
                    !instruction.getFlowType().isComputed()) {
                continue;
            }

            int count = 0;
            for (Reference reference : references.getReferencesFrom(instruction.getAddress(),
                    Reference.MNEMONIC)) {
                if (reference.getReferenceType() == RefType.COMPUTED_JUMP) {
                    count++;
                    destinations.add(reference.getToAddress());
                }
            }
            destinationCounts.add(count);
        }

        Collections.sort(destinationCounts);
        require(destinationCounts.equals(List.of(14, 22)),
            "expected 14- and 22-entry computed jumps, got " + destinationCounts);
        for (Address destination : destinations) {
            require(function.getBody().contains(destination),
                "switch destination is outside the recovered function body: " + destination);
        }

        boolean nativeVariant = currentProgram.getName().contains("native");
        if (nativeVariant) {
            require(preadCount == 0 && nativeLoadCount == 2,
                "native fixture did not contain exactly two native table loads: PREAD=" +
                    preadCount + " native=" + nativeLoadCount);
        }
        else {
            require(preadCount == 4 && nativeLoadCount == 0,
                "program-read fixture did not contain exactly four PREADs: PREAD=" +
                    preadCount + " native=" + nativeLoadCount);
        }

        String c = decompile(function);
        require(!c.contains("Could not recover jumptable"),
            "decompiler still reports an unrecovered jump table");
        require(c.contains("case 0x1ae:") && c.contains("case 0x1c3:") &&
                c.contains("case 0x1e0:") && c.contains("case 0x1ed:"),
            "decompiler did not preserve both original selector ranges\n" + c);

        println("SWITCH_VARIANT=" + (nativeVariant ? "native-load" : "program-read"));
        println("SWITCH_DESTINATION_COUNTS=" + destinationCounts);
        println("SWITCH_BODY_TARGETS=" + destinations.size());
        println("SWITCH_CASE_RANGES=0x1ae-0x1c3,0x1e0-0x1ed");
    }

    private void testCompactValidationFixture() throws Exception {
        Register context = currentProgram.getProgramContext().getRegister("switch_canonical");
        require(context != null, "missing switch_canonical context");

        Map<Long, Integer> expectedReferences = new LinkedHashMap<>();
        expectedReferences.put(VALID_BRANCH, 4);
        expectedReferences.put(SAVED_BRANCH0, 4);
        expectedReferences.put(SAVED_BRANCH1, 3);
        expectedReferences.put(SAVED_P_BRANCH, 25);
        expectedReferences.put(SAVED_HI_BRANCH, 3);
        expectedReferences.put(0x1303cL, 0); // malformed one-entry bound
        expectedReferences.put(0x1304fL, 0); // inconsistent table arithmetic
        expectedReferences.put(0x13062L, 0); // raw target bit 22 set
        expectedReferences.put(0x13075L, 0); // writable table
        expectedReferences.put(0x1307bL, 0); // ordinary indirect branch
        expectedReferences.put(0x1308bL, 0); // known function-entry table

        for (Map.Entry<Long, Integer> entry : expectedReferences.entrySet()) {
            Address address = wordAddress(entry.getKey());
            Instruction instruction = getInstructionAt(address);
            require(instruction != null &&
                    instruction.getMnemonicString().equalsIgnoreCase("LB") &&
                    instruction.getFlowType().isComputed(),
                "expected computed LB at " + address);
            int actual = computedJumpCount(address);
            require(actual == entry.getValue(),
                "computed refs at " + address + ": expected " + entry.getValue() +
                    ", got " + actual);
            require(isCanonical(address, context) == (entry.getValue() > 0),
                "unexpected branch context at " + address);
        }

        require(isCanonical(wordAddress(VALID_INDEX), context),
            "valid compact index was not canonicalized");
        require(isCanonical(wordAddress(0x13096), context) &&
                isCanonical(wordAddress(0x1309c), context),
            "saved-selector range guards were not canonicalized");
        require(isCanonical(wordAddress(0x130a5), context) &&
                isCanonical(wordAddress(0x130af), context),
            "saved-selector dispatch adjustments were not canonicalized");
        require(!isCanonical(wordAddress(0x130a4), context) &&
                !isCanonical(wordAddress(0x130ae), context),
            "saved-selector LSL instructions were unnecessarily canonicalized");
        require(isCanonical(wordAddress(0x130cb), context) &&
                isCanonical(wordAddress(0x130d3), context) &&
                isCanonical(wordAddress(SAVED_P_BRANCH), context),
            "P-saved fall-through switch was not fully canonicalized");
        require(!isCanonical(wordAddress(0x130d2), context),
            "P-saved fall-through LSL was unnecessarily canonicalized");
        require(isCanonical(wordAddress(0x1310c), context) &&
                isCanonical(wordAddress(0x13114), context) &&
                isCanonical(wordAddress(SAVED_HI_BRANCH), context),
            "XAR7-saved HI/fall-through switch was not fully canonicalized");
        require(!isCanonical(wordAddress(0x13113), context),
            "XAR7-saved HI/fall-through LSL was unnecessarily canonicalized");
        Instruction unconditionalDefault = getInstructionAt(wordAddress(0x130a0));
        require(unconditionalDefault != null &&
                unconditionalDefault.getMnemonicString().equalsIgnoreCase("SB") &&
                unconditionalDefault.getFlowType().isJump() &&
                !unconditionalDefault.getFlowType().isConditional() &&
                unconditionalDefault.getFallThrough() == null,
            "SB ...,UNC still exposes a conditional fallthrough");
        require(!isCanonical(wordAddress(0x13035), context),
            "malformed-bound index was canonicalized");
        require(!isCanonical(wordAddress(0x13048), context),
            "inconsistent index was canonicalized");
        require(!isCanonical(wordAddress(0x1305b), context),
            "high-bit table index was canonicalized");
        require(!isCanonical(wordAddress(0x1306e), context),
            "writable-table index was canonicalized");
        require(!isCanonical(wordAddress(0x13084), context),
            "function-pointer index was canonicalized");

        // Prove that each negative fixture still contains the intended defect.
        require(scalarAt(0x13030, 1) == 0,
            "malformed-bound fixture no longer has a one-entry range");
        require(scalarAt(0x1304a, 1) == 0x282,
            "inconsistent-arithmetic fixture no longer has the mismatched adjustment");

        Memory memory = currentProgram.getMemory();
        long highTable = scalarAt(0x13059, 1);
        Address highTableAddress = wordAddress(highTable);
        int wordSize = highTableAddress.getAddressSpace().getAddressableUnitSize();
        long highWord = memory.getShort(highTableAddress.add(wordSize), false) & 0xffffL;
        require((highWord & 0x40) != 0,
            "high-target-bits fixture did not retain raw address bit 22");
        MemoryBlock writable = memory.getBlock(wordAddress(0x2000));
        require(writable != null && writable.isWrite(),
            "writable-table fixture is not in writable memory");
        require(hasCallReference(0x1308c) && hasCallReference(0x1308e) &&
                hasCallReference(0x13090),
            "function-pointer fixture targets are not established call destinations");

        Function function = getFunctionAt(wordAddress(VALID_FUNCTION));
        require(function != null, "missing compact switch function");
        long[] validTargets = { 0x13025, 0x13027, 0x13029, 0x1302b };
        for (long target : validTargets) {
            require(function.getBody().contains(wordAddress(target)),
                "valid switch target not in function body: " + wordAddress(target));
        }

        String c = decompile(function);
        require(!c.contains("Could not recover jumptable"),
            "compact switch remains unrecovered\n" + c);
        require(c.contains("case 0x120:") && c.contains("case 0x123:"),
            "compact switch lost its original nonzero labels\n" + c);

        Function savedFunction = getFunctionAt(wordAddress(SAVED_FUNCTION));
        require(savedFunction != null, "missing saved-selector switch function");
        long[] savedTargets = {
            0x130b6, 0x130b8, 0x130ba, 0x130bc, 0x130be, 0x130c0, 0x130c2
        };
        for (long target : savedTargets) {
            require(savedFunction.getBody().contains(wordAddress(target)),
                "saved-selector switch target not in function body: " + wordAddress(target));
        }
        String savedC = decompile(savedFunction);
        require(!savedC.contains("Could not recover jumptable"),
            "saved-selector switch remains unrecovered\n" + savedC);
        require(savedC.contains("case 0x180:") && savedC.contains("case 0x183:") &&
                (savedC.contains("case 0x190:") || savedC.contains("case 400:")) &&
                savedC.contains("case 0x192:"),
            "saved-selector switch lost its original nonzero labels\n" + savedC);

        Function savedPFunction = getFunctionAt(wordAddress(SAVED_P_FUNCTION));
        require(savedPFunction != null, "missing P-saved fall-through switch function");
        long[] savedPTargets = { 0x130da, 0x130fc, 0x130fe, 0x13108 };
        for (long target : savedPTargets) {
            require(savedPFunction.getBody().contains(wordAddress(target)),
                "P-saved switch target not in function body: " + wordAddress(target));
        }
        String savedPC = decompile(savedPFunction);
        require(!savedPC.contains("Could not recover jumptable") &&
                !savedPC.contains("Treating indirect jump as call"),
            "P-saved fall-through switch remains unrecovered\n" + savedPC);
        require(savedPC.contains("case 0x200:") && savedPC.contains("case 0x211:") &&
                savedPC.contains("case 0x216:") && savedPC.contains("case 0x21b:"),
            "P-saved switch lost its original nonzero labels\n" + savedPC);

        Function savedHiFunction = getFunctionContaining(wordAddress(SAVED_HI_FUNCTION));
        require(savedHiFunction != null,
            "missing XAR7-saved HI/fall-through switch function");
        long[] savedHiTargets = { 0x1311b, 0x1311d, 0x1311f };
        for (long target : savedHiTargets) {
            require(savedHiFunction.getBody().contains(wordAddress(target)),
                "XAR7-saved HI switch target not in function body: " + wordAddress(target));
        }
        String savedHiC = decompile(savedHiFunction);
        require(!savedHiC.contains("Could not recover jumptable") &&
                savedHiC.contains("case 0x220:") && savedHiC.contains("case 0x222:"),
            "XAR7-saved HI/fall-through switch remains unrecovered\n" + savedHiC);

        println("SWITCH_VALIDATION_POSITIVE_REFS=4,4,3,25,3");
        println("SWITCH_VALIDATION_REJECTED=6");
        println("SWITCH_VALIDATION_CASE_RANGES=" +
            "0x120-0x123,0x180-0x183,0x190-0x192,0x200-0x21b,0x220-0x222");
        println("SWITCH_VALIDATION_BODY_TARGETS=4,7,24,3");
    }

    private String decompile(Function function) {
        DecompInterface decompiler = new DecompInterface();
        require(decompiler.openProgram(currentProgram), "failed to open decompiler");
        DecompileResults results = decompiler.decompileFunction(function, 30, monitor);
        decompiler.dispose();
        require(results.decompileCompleted(),
            "decompile failed: " + results.getErrorMessage());
        return results.getDecompiledFunction().getC();
    }

    private Address wordAddress(long wordOffset) {
        int wordSize = currentProgram.getAddressFactory()
                .getDefaultAddressSpace()
                .getAddressableUnitSize();
        return currentProgram.getAddressFactory()
                .getDefaultAddressSpace()
                .getAddress(wordOffset * wordSize);
    }

    private int computedJumpCount(Address address) {
        return computedJumpDestinations(address).size();
    }

    private List<Address> computedJumpDestinations(Address address) {
        List<Address> destinations = new ArrayList<>();
        ReferenceManager references = currentProgram.getReferenceManager();
        for (Reference reference : references.getReferencesFrom(address, Reference.MNEMONIC)) {
            if (reference.getReferenceType() == RefType.COMPUTED_JUMP) {
                destinations.add(reference.getToAddress());
            }
        }
        return destinations;
    }

    private boolean isCanonical(Address address, Register context) {
        return BigInteger.ONE.equals(
            currentProgram.getProgramContext().getValue(context, address, false));
    }

    private void requireNoFfcReturnContext() {
        Register context = currentProgram.getProgramContext().getRegister("ffc_return");
        require(context != null, "missing ffc_return context");
        InstructionIterator instructions = currentProgram.getListing().getInstructions(true);
        while (instructions.hasNext()) {
            Instruction instruction = instructions.next();
            require(!isCanonical(instruction.getAddress(), context),
                "switch fixture unexpectedly selected FFC return semantics at " +
                    instruction.getAddress());
        }
    }

    private boolean hasPcodeOp(Instruction instruction, int opcode) {
        if (instruction == null) {
            return false;
        }
        for (PcodeOp operation : instruction.getPcode()) {
            if (operation.getOpcode() == opcode) {
                return true;
            }
        }
        return false;
    }

    private boolean hasFlowReferenceFromTo(long fromWord, long toWord) {
        for (Reference reference : currentProgram.getReferenceManager()
                .getReferencesFrom(wordAddress(fromWord))) {
            if (reference.getReferenceType().isFlow() &&
                    reference.getToAddress().equals(wordAddress(toWord))) {
                return true;
            }
        }
        return false;
    }

    private boolean hasCallReference(long wordOffset) {
        ReferenceIterator references =
            currentProgram.getReferenceManager().getReferencesTo(wordAddress(wordOffset));
        while (references.hasNext()) {
            if (references.next().getReferenceType().isCall()) {
                return true;
            }
        }
        return false;
    }

    private boolean hasCallReferenceFromMnemonic(long targetWord, String mnemonic) {
        ReferenceIterator references =
            currentProgram.getReferenceManager().getReferencesTo(wordAddress(targetWord));
        while (references.hasNext()) {
            Reference reference = references.next();
            if (!reference.getReferenceType().isCall()) {
                continue;
            }
            Instruction source = getInstructionAt(reference.getFromAddress());
            if (source != null && source.getMnemonicString().equalsIgnoreCase(mnemonic)) {
                return true;
            }
        }
        return false;
    }

    private long scalarAt(long wordOffset, int operand) {
        Instruction instruction = getInstructionAt(wordAddress(wordOffset));
        require(instruction != null, "missing fixture instruction at " + wordAddress(wordOffset));
        Scalar scalar = instruction.getScalar(operand);
        require(scalar != null, "missing fixture scalar at " + wordAddress(wordOffset));
        return scalar.getUnsignedValue();
    }

    private boolean isUnsignedHiGuard(Instruction instruction) {
        return instruction != null && instruction.getFlowType().isJump() &&
            instruction.getFlowType().isConditional() &&
            (instruction.getMnemonicString().equalsIgnoreCase("SB") ||
                instruction.getMnemonicString().equalsIgnoreCase("B") ||
                instruction.getMnemonicString().equalsIgnoreCase("BF")) &&
            instruction.getNumOperands() > 1 &&
            instruction.getDefaultOperandRepresentation(1).equalsIgnoreCase("HI");
    }

    private boolean isRegisterMove(Instruction instruction, String mnemonic,
            String destination, String source) {
        return instruction != null &&
            instruction.getMnemonicString().equalsIgnoreCase(mnemonic) &&
            isRegisterOperand(instruction, 0, destination) &&
            isRegisterOperand(instruction, 1, source);
    }

    private boolean isRegisterOperand(Instruction instruction, int operand, String name) {
        if (instruction == null || operand >= instruction.getNumOperands()) {
            return false;
        }
        Register register = instruction.getRegister(operand);
        if (register != null) {
            return register.getName().equalsIgnoreCase(name);
        }
        Object[] objects = instruction.getOpObjects(operand);
        return objects.length == 1 && objects[0] instanceof Register objectRegister &&
            objectRegister.getName().equalsIgnoreCase(name);
    }

    private long scalarUnsigned(Instruction instruction, int operand) {
        require(instruction != null && operand < instruction.getNumOperands(),
            "missing scalar operand " + operand);
        Scalar scalar = instruction.getScalar(operand);
        require(scalar != null, "missing scalar operand at " + instruction.getAddress());
        return scalar.getUnsignedValue();
    }

    private Instruction contiguousPrevious(Instruction instruction) {
        if (instruction == null) {
            return null;
        }
        Instruction previous = instruction.getPrevious();
        return previous != null &&
            previous.getMaxAddress().next().equals(instruction.getMinAddress())
                ? previous
                : null;
    }
}
