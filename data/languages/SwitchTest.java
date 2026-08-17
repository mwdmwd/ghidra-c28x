import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.plugin.core.analysis.TMS320C28SwitchAnalyzer;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.JumpTable;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

public class SwitchTest extends GhidraScript {
    private static final String SWITCH_OWNER_MARKER =
        "tms320c28_switch_analyzer_owned";
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
        if (name.contains("saved_layout_validation")) {
            testSavedSelectorLayoutValidationFixture();
        }
        else if (name.contains("ar6_validation")) {
            testAr6ValidationFixture();
        }
        else if (name.contains("saved_validation")) {
            testSavedSelectorValidationFixture();
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

    private void testSavedSelectorLayoutValidationFixture() throws Exception {
        Register context = currentProgram.getProgramContext().getRegister("switch_canonical");
        require(context != null, "missing switch_canonical context");

        long[] canonicalSites = { 0x1801a, 0x1801e, 0x18038, 0x1803c };
        for (long word : canonicalSites) {
            require(isCanonical(wordAddress(word), context),
                "non-adjacent saved-selector site was not canonicalized at " +
                    wordAddress(word));
        }
        int tagged = 0;
        InstructionIterator instructions = currentProgram.getListing().getInstructions(true);
        while (instructions.hasNext()) {
            if (isCanonical(instructions.next().getAddress(), context)) {
                tagged++;
            }
        }
        require(tagged == canonicalSites.length,
            "unexpected non-adjacent saved-selector canonical-site count: " + tagged);

        long[] globalTargets = { 0x1800b, 0x1800d, 0x1800f, 0x18011 };
        long[] stackTargets = { 0x18025, 0x18028, 0x1802b, 0x1802e };
        requireExactComputedTargets(0x1801e, globalTargets,
            "non-adjacent global saved AR6");
        requireExactComputedTargets(0x1803c, stackTargets,
            "non-adjacent stack saved AR6");
        requireOwnedSwitchOverride(0x1801e, true,
            "non-adjacent global saved AR6");
        requireOwnedSwitchOverride(0x1803c, true,
            "non-adjacent stack saved AR6");

        requireCompleteSwitch(0x18005, 0x1801e, 0x1801f, globalTargets, 0, 3,
            "non-adjacent global saved AR6");
        requireCompleteSwitch(0x18021, 0x1803c, 0x1803d, stackTargets, 0, 3,
            "non-adjacent stack saved AR6");

        requireNonAdjacentIngress(0x18009, 0x18013,
            "non-adjacent global saved AR6");
        requireNonAdjacentIngress(0x18023, 0x18031,
            "non-adjacent stack saved AR6");

        requireWords(0x18006, 0x761f, 0x0090);
        requireWords(0x18009, 0xffef, 0x000a);
        requireWords(0x1801a, 0x5604, 0x01a6);
        requireWords(0x1801e, 0x7620);
        requireWords(0x18021, 0xfe02);
        requireWords(0x18022, 0x9641);
        requireWords(0x18023, 0xffef, 0x000e);
        requireWords(0x18038, 0x5604, 0x01a6);
        requireWords(0x1803c, 0x7620);
        requireInstructionText(0x18006, "movw DP,#0x90");
        requireInstructionText(0x1801a, "add ACC,AR6 << #0x1");
        requireInstructionText(0x1801e, "lb *XAR7");
        requireInstructionText(0x18021, "addb SP,#0x2");
        requireInstructionText(0x18022, "mov *-SP[0x1],AL");
        requireInstructionText(0x18038, "add ACC,AR6 << #0x1");
        requireInstructionText(0x1803c, "lb *XAR7");
        requireOrdinaryIndirectBranch(0x1801e);
        requireOrdinaryIndirectBranch(0x1803c);

        println("SWITCH_SAVED_LAYOUT_POSITIVE_REFS=4,4");
        println("SWITCH_SAVED_LAYOUT_CANONICAL_SITES=" + tagged);
        println("SWITCH_SAVED_LAYOUT_CASE_RANGES=0-3,0-3");
        println("SWITCH_SAVED_LAYOUT_OWNED_OVERRIDES=2");
    }

    private void requireNonAdjacentIngress(long ingressWord, long compareWord,
            String description) {
        Instruction ingress = getInstructionAt(wordAddress(ingressWord));
        Instruction compare = getInstructionAt(wordAddress(compareWord));
        require(ingress != null && compare != null,
            description + " lost its ingress or compare instruction");
        Address[] flows = ingress.getFlows();
        require(flows.length == 1 && flows[0].equals(compare.getMinAddress()),
            description + " ingress no longer branches directly to the compare");
        require(compare.getPrevious() != null && !compare.getPrevious().equals(ingress),
            description + " fixture no longer places case bodies between ingress and compare");
        require(!compare.getPrevious().getFlowType().hasFallthrough(),
            description + " physical predecessor now falls through into the dispatcher");
    }

    private void testSavedSelectorValidationFixture() throws Exception {
        Register context = currentProgram.getProgramContext().getRegister("switch_canonical");
        require(context != null, "missing switch_canonical context");

        long[] canonicalSites = {
            0x17046, 0x1704a,
            0x1705f, 0x17063,
            0x17071, 0x17078, 0x1707c
        };
        for (long word : canonicalSites) {
            require(isCanonical(wordAddress(word), context),
                "saved-selector positive site was not canonicalized at " + wordAddress(word));
        }
        require(!isCanonical(wordAddress(0x17077), context),
            "SUBB switch LSL must retain ordinary context");

        long[] globalTargets = { 0x1704d, 0x1704f, 0x17051, 0x17053 };
        long[] stackTargets = { 0x17066, 0x17068, 0x1706a, 0x1706c };
        long[] subbTargets = { 0x1707f, 0x17081, 0x17083, 0x17085 };
        requireExactComputedTargets(0x1704a, globalTargets, "global saved AR6");
        requireExactComputedTargets(0x17063, stackTargets, "stack saved AR6");
        requireExactComputedTargets(0x1707c, subbTargets, "saved SUBB");

        int tagged = 0;
        InstructionIterator instructions = currentProgram.getListing().getInstructions(true);
        while (instructions.hasNext()) {
            if (isCanonical(instructions.next().getAddress(), context)) {
                tagged++;
            }
        }
        require(tagged == canonicalSites.length,
            "unexpected saved-selector canonical-site count: " + tagged);

        // The two AR6 schedules require a generic analyzer-owned descriptor;
        // the SUBB form is recovered by stock Switch Analysis from canonical
        // arithmetic alone.
        requireOwnedSwitchOverride(0x1704a, true, "global saved AR6");
        requireOwnedSwitchOverride(0x17063, true, "stack saved AR6");
        requireOwnedSwitchOverride(0x1707c, false, "saved SUBB");

        requireCompleteSwitch(0x1703b, 0x1704a, 0x1704b, globalTargets, 0, 3,
            "global saved AR6");
        requireCompleteSwitch(0x17055, 0x17063, 0x17064, stackTargets, 0, 3,
            "stack saved AR6");
        requireCompleteSwitch(0x1706e, 0x1707c, 0x1707d, subbTargets, 1, 4,
            "saved SUBB");

        // Context changes must not alter bytes or rendering.  These words are
        // the exact linked TI encodings, including both canonical SUBBs.
        requireWords(0x17046, 0x5604, 0x01a6);
        requireWords(0x1704a, 0x7620);
        requireWords(0x1705f, 0x5604, 0x01a6);
        requireWords(0x17063, 0x7620);
        requireWords(0x17071, 0x1901);
        requireWords(0x17077, 0xff30);
        requireWords(0x17078, 0x1902);
        requireWords(0x1707c, 0x7620);
        requireInstructionText(0x17046, "add ACC,AR6 << #0x1");
        requireInstructionText(0x1704a, "lb *XAR7");
        requireInstructionText(0x1705f, "add ACC,AR6 << #0x1");
        requireInstructionText(0x17063, "lb *XAR7");
        requireInstructionText(0x17071, "subb ACC,#0x1");
        requireInstructionText(0x17078, "subb ACC,#0x2");
        requireInstructionText(0x1707c, "lb *XAR7");

        requireCanonicalSubbPcode(0x17071);
        requireCanonicalSubbPcode(0x17078);
        requireOrdinaryIndirectBranch(0x1704a);
        requireOrdinaryIndirectBranch(0x17063);
        requireOrdinaryIndirectBranch(0x1707c);

        long[] nearMissBranches = {
            0x17096, 0x170ae, 0x170c7, 0x170df, 0x170f7, 0x17110,
            0x17128, 0x17140, 0x17158, 0x17170, 0x17188, 0x171a0,
            0x171b8, 0x171d0, 0x171ea, 0x17202, 0x1721a, 0x17231,
            0x17248, 0x1725f, 0x17276, 0x1728d, 0x172a4
        };
        long[] nearMissAdds = {
            0x17092, 0x170aa, 0x170c3, 0x170db, 0x170f3, 0x1710c,
            0x17124, 0x1713c, 0x17154, 0x1716c, 0x17184, 0x1719c,
            0x171b4, 0x171cc, 0x171e6, 0x171fe, 0x17216, 0x1722d
        };
        for (long branch : nearMissBranches) {
            require(!isCanonical(wordAddress(branch), context),
                "near miss branch was canonicalized at " + wordAddress(branch));
            requireOwnedSwitchOverride(branch, false, "near miss " + wordAddress(branch));
            requireOrdinaryIndirectBranch(branch);
        }
        for (long add : nearMissAdds) {
            require(!isCanonical(wordAddress(add), context),
                "near miss ADD was canonicalized at " + wordAddress(add));
        }

        long[] ordinarySubbs = {
            0x1723d, 0x17244, 0x17254, 0x1725b, 0x1726b,
            0x17272, 0x17282, 0x17289, 0x17299, 0x172a0
        };
        for (long subb : ordinarySubbs) {
            require(!isCanonical(wordAddress(subb), context),
                "near miss SUBB was canonicalized at " + wordAddress(subb));
            requireOrdinarySubbPcode(subb);
        }

        // Prove every relaxed condition remains isolated in the linked image.
        require(isRegisterOperand(getInstructionAt(wordAddress(0x17088)), 1, "AH"),
            "save-source near miss no longer stores AH");
        require(getInstructionAt(wordAddress(0x170a4))
                .getDefaultOperandRepresentation(1).contains("0x2"),
            "reload-slot near miss no longer reloads the alternate slot");
        require(getInstructionAt(wordAddress(0x170b9)).getMnemonicString()
                .equalsIgnoreCase("MOVB"),
            "partial-overwrite near miss lost its byte write");
        require(isRegisterOperand(getInstructionAt(wordAddress(0x170d4)), 0, "AH"),
            "compare-register near miss no longer compares AH");
        require(getInstructionAt(wordAddress(0x170ee))
                .getDefaultOperandRepresentation(1).equalsIgnoreCase("GEQ"),
            "guard-condition near miss no longer uses GEQ");
        require(getInstructionAt(wordAddress(0x17106)).getMnemonicString()
                .equalsIgnoreCase("ADDB"),
            "flag-changing near miss lost the intervening ADDB");
        require(hasFlowReferenceFromTo(0x172ad, 0x1711d),
            "alternate dispatcher ingress is no longer present");
        require(hasFlowReferenceFromTo(0x172af, 0x1713c),
            "interior dispatcher ingress is no longer present");
        require(getInstructionAt(wordAddress(0x17152)).getMnemonicString()
                .equalsIgnoreCase("CLRC"),
            "global CLRC near miss no longer clears SXM");
        require(getInstructionAt(wordAddress(0x1722b)).getMnemonicString()
                .equalsIgnoreCase("SETC"),
            "stack SETC near miss no longer sets SXM");
        require(isRegisterOperand(getInstructionAt(wordAddress(0x1716c)), 1, "AR5"),
            "wrong-index-source near miss no longer uses AR5");
        require(scalarAt(0x17184, 2) == 2,
            "wrong-scale near miss no longer shifts by two");
        require(scalarAt(0x17198, 1) == 0x1730f,
            "table-base near miss no longer points one word into the table");

        Memory memory = currentProgram.getMemory();
        MemoryBlock writable = memory.getBlock(wordAddress(0x230a));
        require(writable != null && writable.isInitialized() && writable.isLoaded() &&
                writable.isRead() && writable.isWrite(),
            "writable-table near miss is not in initialized writable memory");
        MemoryBlock shortTable = memory.getBlock(wordAddress(0x1f000));
        int wordSize = wordAddress(0).getAddressSpace().getAddressableUnitSize();
        Address requiredShortEnd = wordAddress(0x1f000).add(4L * 2 * wordSize - 1);
        require(shortTable != null && !shortTable.contains(requiredShortEnd),
            "short-table near miss unexpectedly contains four entries");
        long highWord = memory.getShort(wordAddress(0x17315), false) & 0xffffL;
        require((highWord & 0x40) != 0,
            "high-target-bits near miss no longer sets raw address bit 22");
        MemoryBlock nonExecutable = memory.getBlock(wordAddress(0x2306));
        require(nonExecutable != null && !nonExecutable.isExecute(),
            "non-executable target near miss became executable");
        require(hasCallReference(0x172b1),
            "called-target near miss lost its ordinary call destination");
        require(computedJumpCount(wordAddress(0x1721a)) == 0,
            "called-target near miss gained computed switch references");

        require(scalarAt(0x1723d, 1) == 2,
            "guard-SUBB immediate near miss no longer uses two");
        require(scalarAt(0x1725b, 1) == 4,
            "tail-SUBB immediate near miss no longer uses four");
        require(scalarAt(0x17269, 1) == 0,
            "bound near miss no longer has a one-entry range");
        require(isRegisterOperand(getInstructionAt(wordAddress(0x17285)), 1, "P"),
            "selector-reload near miss no longer reloads P");
        require(getInstructionAt(wordAddress(0x17297)).getMnemonicString()
                .equalsIgnoreCase("MOVL") &&
                !isRegisterOperand(getInstructionAt(wordAddress(0x17297)), 1, "XAR7"),
            "unsafe-range near miss no longer loads an unproved memory bound");
        require(scalarAt(0x17299, 1) == 1 && scalarAt(0x172a0, 1) == 2,
            "unsafe-range near miss changed either exact SUBB immediate");

        // The pre-analysis seed deliberately supplied stale context, edges,
        // body membership, and an owned override for the reload-slot near miss.
        // All four conclusions must be revoked without changing its bytes/text.
        require(!isCanonical(wordAddress(0x170aa), context) &&
                !isCanonical(wordAddress(0x170ae), context),
            "stale saved-selector context survived revalidation");
        require(computedJumpCount(wordAddress(0x170ae)) == 0,
            "stale saved-selector computed references survived revalidation");
        requireOwnedSwitchOverride(0x170ae, false, "stale reload-slot descriptor");
        require(switchOverrideNamespace(0x170ae) == null,
            "stale reload-slot jump namespace survived complete revocation");
        Function stale = getFunctionContaining(wordAddress(0x1709f));
        require(stale != null, "missing stale-seed function after analysis");
        for (long target : new long[] { 0x170b1, 0x170b3, 0x170b5 }) {
            require(!stale.getBody().contains(wordAddress(target)),
                "stale target survived function-body repair: " + wordAddress(target));
        }
        requireWords(0x170aa, 0x5604, 0x01a6);
        requireWords(0x170ae, 0x7620);
        requireInstructionText(0x170aa, "add ACC,AR6 << #0x1");
        requireInstructionText(0x170ae, "lb *XAR7");

        println("SWITCH_STALE_NAMESPACE_REMOVED=" + wordAddress(0x170ae));
        println("SWITCH_STALE_REVOCATION_COMPLETE=1");

        testOwnedSwitchLifecycle(context, globalTargets);
        testUserOwnedNamespaceControls(context, stackTargets);

        println("SWITCH_SAVED_POSITIVE_REFS=4,4,4");
        println("SWITCH_SAVED_CANONICAL_SITES=" + tagged);
        println("SWITCH_SAVED_CASE_RANGES=0-3,0-3,1-4");
        println("SWITCH_SAVED_REJECTED_NEAR_MISSES=" + nearMissBranches.length);
        println("SWITCH_SAVED_STALE_REVOCATION=PASS");
        println("SWITCH_SAVED_OWNED_OVERRIDES=2");
    }

    private void testOwnedSwitchLifecycle(Register context, long[] targetWords)
            throws Exception {
        long functionWord = 0x1703b;
        long modeWord = 0x17044;
        long addWord = 0x17046;
        long branchWord = 0x1704a;
        long defaultWord = 0x1704b;
        Address modeAddress = wordAddress(modeWord);
        Address branchAddress = wordAddress(branchWord);
        Memory memory = currentProgram.getMemory();
        int originalModeWord = memory.getShort(modeAddress, false) & 0xffff;
        String originalModeText = instructionText(modeWord);
        List<Address> originalTargets = sortedAddresses(targetWords);

        Function function = getFunctionContaining(wordAddress(functionWord));
        require(function != null, "missing lifecycle switch function");
        require(isCanonical(wordAddress(addWord), context) &&
                isCanonical(branchAddress, context),
            "lifecycle switch did not begin canonicalized");
        require(computedJumpDestinations(branchAddress).equals(originalTargets),
            "lifecycle switch did not begin with the exact target set");
        Namespace initialNamespace = switchOverrideNamespace(branchWord);
        requireOwnedNamespaceDescriptor(branchWord, targetWords,
            "initial lifecycle descriptor");
        NamespaceState initialState = namespaceState(initialNamespace);
        require(initialState.children.size() == targetWords.length + 2,
            "initial lifecycle namespace has the wrong child count: " + initialState);
        String initialC = decompile(function);
        require(hasCaseLabel(initialC, 0) && hasCaseLabel(initialC, 3),
            "initial lifecycle switch did not decompile with cases 0-3\n" + initialC);

        Reference userReference = currentProgram.getReferenceManager().addMemoryReference(
            branchAddress, wordAddress(defaultWord), RefType.COMPUTED_JUMP,
            SourceType.USER_DEFINED, Reference.MNEMONIC);
        require(userReference != null, "could not seed user computed-jump reference");

        // Changing only the explicit SXM mode makes the global saved-selector
        // schedule fail its finite variant proof while leaving the dispatch and
        // table bytes otherwise intact.
        replaceInstructionWord(modeWord, 0x2901);
        requireInstructionText(modeWord, "clrc 0x1");
        rerunSwitchAnalyzer("lifecycle invalidation");

        function = getFunctionContaining(wordAddress(functionWord));
        require(function != null, "lifecycle function disappeared after invalidation");
        require(!isCanonical(wordAddress(addWord), context) &&
                !isCanonical(branchAddress, context),
            "invalid lifecycle switch retained canonical context");
        require(computedJumpCount(branchAddress, SourceType.ANALYSIS) == 0,
            "invalid lifecycle switch retained analyzer references");
        require(hasComputedJumpReference(branchAddress, wordAddress(defaultWord),
                SourceType.USER_DEFINED),
            "owned-state revocation removed the user computed-jump reference");
        require(computedJumpCount(branchAddress, SourceType.USER_DEFINED) == 1,
            "unexpected user computed-jump reference count after invalidation");
        require(switchOverrideNamespace(branchWord) == null,
            "invalid lifecycle switch retained its exact jump namespace");
        for (long targetWord : targetWords) {
            require(!function.getBody().contains(wordAddress(targetWord)),
                "invalid lifecycle target remained in the function body: " +
                    wordAddress(targetWord));
        }
        String invalidC = decompile(function);
        require(!(hasCaseLabel(invalidC, 0) && hasCaseLabel(invalidC, 3)),
            "invalid lifecycle switch still decompiled as the complete old switch\n" +
                invalidC);
        requireWords(modeWord, 0x2901);
        requireWords(addWord, 0x5604, 0x01a6);
        requireWords(branchWord, 0x7620);
        requireInstructionText(addWord, "add ACC,AR6 << #0x1");
        requireInstructionText(branchWord, "lb *XAR7");
        println("SWITCH_LIFECYCLE_INVALIDATED=1");
        println("SWITCH_LIFECYCLE_USER_REFERENCE_PRESERVED=1");

        removeComputedJumpReferences(branchAddress, SourceType.USER_DEFINED);
        require(!hasComputedJumpReference(branchAddress, wordAddress(defaultWord),
                SourceType.USER_DEFINED),
            "could not remove lifecycle user-reference seed before restoration");
        replaceInstructionWord(modeWord, originalModeWord);
        require(instructionText(modeWord).equals(originalModeText),
            "restored lifecycle evidence did not reproduce its original text");
        rerunSwitchAnalyzer("lifecycle restoration");

        function = getFunctionContaining(wordAddress(functionWord));
        require(function != null, "lifecycle function disappeared after restoration");
        require(isCanonical(wordAddress(addWord), context) &&
                isCanonical(branchAddress, context),
            "restored lifecycle switch did not regain canonical context");
        requireExactComputedTargets(branchWord, targetWords,
            "restored lifecycle descriptor");
        requireOwnedNamespaceDescriptor(branchWord, targetWords,
            "restored lifecycle descriptor");
        requireCompleteSwitch(functionWord, branchWord, defaultWord, targetWords, 0, 3,
            "restored lifecycle descriptor");
        requireWords(modeWord, originalModeWord);
        require(instructionText(modeWord).equals(originalModeText),
            "restored lifecycle instruction text changed");
        println("SWITCH_LIFECYCLE_REPUBLISHED_TARGETS=" + targetWords.length);
        println("SWITCH_LIFECYCLE_NAMESPACE_CHILDREN=" +
            namespaceState(switchOverrideNamespace(branchWord)).children.size());

        NamespaceSemanticState namespaceBefore = namespaceSemanticState(
            switchOverrideNamespace(branchWord));
        List<String> referencesBefore = computedReferenceSignatures(branchAddress);
        String bodyBefore = function.getBody().toString();
        String decompilationBefore = normalizeText(decompile(function));
        rerunSwitchAnalyzer("lifecycle idempotence");

        function = getFunctionContaining(wordAddress(functionWord));
        require(function != null, "lifecycle function disappeared on idempotent rerun");
        require(namespaceBefore.equals(namespaceSemanticState(
                switchOverrideNamespace(branchWord))),
            "idempotent rerun changed the owned namespace descriptor");
        require(referencesBefore.equals(computedReferenceSignatures(branchAddress)),
            "idempotent rerun changed computed-reference state");
        require(bodyBefore.equals(function.getBody().toString()),
            "idempotent rerun changed the containing function body");
        require(decompilationBefore.equals(normalizeText(decompile(function))),
            "idempotent rerun changed decompilation");
        require(isCanonical(wordAddress(addWord), context) &&
                isCanonical(branchAddress, context),
            "idempotent rerun changed canonical context");
        requireWords(modeWord, originalModeWord);
        require(instructionText(modeWord).equals(originalModeText),
            "idempotent rerun changed restored fixture evidence");
        println("SWITCH_LIFECYCLE_IDEMPOTENT=1");
    }

    private void testUserOwnedNamespaceControls(Register context, long[] targetWords)
            throws Exception {
        long functionWord = 0x17055;
        long addWord = 0x1705f;
        long branchWord = 0x17063;
        long defaultWord = 0x17064;
        Address branch = wordAddress(branchWord);
        Function function = getFunctionContaining(wordAddress(functionWord));
        require(function != null, "missing user-control switch function");
        requireOwnedNamespaceDescriptor(branchWord, targetWords,
            "initial user-control descriptor");

        removeOwnedSwitchStateForTest(function, branchWord);
        Namespace empty = createStandardSwitchNamespace(function, branchWord);
        NamespaceState emptyBefore = namespaceState(empty);
        require(emptyBefore.children.isEmpty(),
            "empty user namespace unexpectedly has children: " + emptyBefore);
        rerunSwitchAnalyzer("empty user namespace control");
        Namespace emptyAfter = switchOverrideNamespace(branchWord);
        require(emptyAfter != null && emptyBefore.equals(namespaceState(emptyAfter)),
            "analyzer changed the empty unmarked user namespace");
        require(!hasExactOwnerMarker(branchWord, SourceType.ANALYSIS),
            "analyzer marked the empty user namespace");
        println("SWITCH_USER_EMPTY_NAMESPACE_PRESERVED=1");
        deleteNamespaceForTest(emptyAfter, "empty user namespace");
        removeComputedJumpReferences(branch, SourceType.ANALYSIS);
        CreateFunctionCmd.fixupFunctionBody(currentProgram, function, monitor);

        ArrayList<Address> targets = new ArrayList<>(sortedAddresses(targetWords));
        new JumpTable(branch, targets, true, 0).writeOverride(function);
        Namespace manual = switchOverrideNamespace(branchWord);
        require(manual != null, "manual JumpTable override was not created");
        require(JumpTable.readOverride(manual, currentProgram.getSymbolTable()) != null,
            "manual JumpTable override is unreadable");
        NamespaceState manualBefore = namespaceState(manual);
        require(manualBefore.children.size() == targetWords.length + 1,
            "manual JumpTable override has the wrong child count: " + manualBefore);
        rerunSwitchAnalyzer("nonempty user namespace control");
        Namespace manualAfter = switchOverrideNamespace(branchWord);
        require(manualAfter != null && manualBefore.equals(namespaceState(manualAfter)),
            "analyzer changed the nonempty unmarked user namespace");
        require(!hasExactOwnerMarker(branchWord, SourceType.ANALYSIS),
            "analyzer claimed the manual JumpTable override");
        println("SWITCH_USER_NONEMPTY_NAMESPACE_CHILDREN=" +
            manualBefore.children.size());

        HighFunction.createLabelSymbol(currentProgram.getSymbolTable(), branch,
            SWITCH_OWNER_MARKER, manualAfter, SourceType.USER_DEFINED, false);
        NamespaceState userMarkerBefore = namespaceState(manualAfter);
        rerunSwitchAnalyzer("non-analysis owner-marker control");
        Namespace userMarkerAfter = switchOverrideNamespace(branchWord);
        require(userMarkerAfter != null &&
                userMarkerBefore.equals(namespaceState(userMarkerAfter)),
            "analyzer treated a non-analysis owner-name symbol as ownership");
        require(hasExactOwnerMarker(branchWord, SourceType.USER_DEFINED),
            "non-analysis owner-name symbol did not survive");
        println("SWITCH_USER_SOURCE_MARKER_PRESERVED=1");
        deleteNamespaceForTest(userMarkerAfter, "manual user namespace");
        removeComputedJumpReferences(branch, SourceType.ANALYSIS);
        CreateFunctionCmd.fixupFunctionBody(currentProgram, function, monitor);

        Namespace wrongAddress = createStandardSwitchNamespace(function, branchWord);
        HighFunction.createLabelSymbol(currentProgram.getSymbolTable(),
            wordAddress(defaultWord), SWITCH_OWNER_MARKER, wrongAddress,
            SourceType.ANALYSIS, false);
        NamespaceState wrongAddressBefore = namespaceState(wrongAddress);
        rerunSwitchAnalyzer("wrong-address owner-marker control");
        Namespace wrongAddressAfter = switchOverrideNamespace(branchWord);
        require(wrongAddressAfter != null &&
                wrongAddressBefore.equals(namespaceState(wrongAddressAfter)),
            "wrong-address analysis marker granted namespace ownership");
        require(!hasExactOwnerMarker(branchWord, SourceType.ANALYSIS),
            "wrong-address marker was mistaken for the exact owner marker");
        println("SWITCH_USER_WRONG_ADDRESS_MARKER_PRESERVED=1");
        deleteNamespaceForTest(wrongAddressAfter, "wrong-address user namespace");
        removeComputedJumpReferences(branch, SourceType.ANALYSIS);
        CreateFunctionCmd.fixupFunctionBody(currentProgram, function, monitor);

        rerunSwitchAnalyzer("restore user-control switch");
        function = getFunctionContaining(wordAddress(functionWord));
        require(function != null, "user-control switch function disappeared");
        require(isCanonical(wordAddress(addWord), context) && isCanonical(branch, context),
            "user-control switch did not regain canonical context");
        requireOwnedNamespaceDescriptor(branchWord, targetWords,
            "restored user-control descriptor");
        requireCompleteSwitch(functionWord, branchWord, defaultWord, targetWords, 0, 3,
            "restored user-control descriptor");

        long outsideBranchWord = 0x170ae;
        Address outsideBranch = wordAddress(outsideBranchWord);
        Function outsideFunction = getFunctionContaining(outsideBranch);
        require(outsideFunction != null, "missing outside-marker control function");
        require(switchOverrideNamespace(outsideBranchWord) == null,
            "outside-marker control unexpectedly has a standard jump namespace");
        Namespace outside = currentProgram.getSymbolTable().createNameSpace(outsideFunction,
            "jmp_" + outsideBranch, SourceType.USER_DEFINED);
        HighFunction.createLabelSymbol(currentProgram.getSymbolTable(), outsideBranch,
            SWITCH_OWNER_MARKER, outside, SourceType.ANALYSIS, false);
        NamespaceState outsideBefore = namespaceState(outside);
        rerunSwitchAnalyzer("outside owner-marker control");
        Namespace outsideAfter = findDirectChildNamespace(outsideFunction,
            "jmp_" + outsideBranch);
        require(outsideAfter != null && outsideBefore.equals(namespaceState(outsideAfter)),
            "analysis marker outside the standard override namespace was changed");
        require(switchOverrideNamespace(outsideBranchWord) == null,
            "outside marker caused creation of a standard stale namespace");
        println("SWITCH_OUTSIDE_ANALYSIS_MARKER_PRESERVED=1");
        deleteNamespaceForTest(outsideAfter, "outside analysis-marker namespace");

        requireOwnedNamespaceDescriptor(branchWord, targetWords,
            "final user-control descriptor");
        requireExactComputedTargets(branchWord, targetWords,
            "final user-control descriptor");
        println("SWITCH_USER_NAMESPACE_CONTROLS=5");
    }

    private void requireCompleteSwitch(long functionWord, long branchWord, long defaultWord,
            long[] targetWords, int lowCase, int highCase, String description) {
        Function function = getFunctionContaining(wordAddress(functionWord));
        require(function != null, "missing " + description + " function");
        require(function.getBody().contains(wordAddress(defaultWord)),
            description + " default is outside the function body");
        for (long targetWord : targetWords) {
            Address target = wordAddress(targetWord);
            require(function.getBody().contains(target),
                description + " target is outside function body: " + target);
            require(getInstructionAt(target) != null,
                description + " target was not disassembled: " + target);
            require(!hasCallReference(targetWord),
                description + " target was classified as a function/call: " + target);
            require(getFunctionAt(target) == null,
                description + " target became a separate function: " + target);
        }
        String c = decompile(function);
        require(!c.contains("Could not recover jumptable") &&
                !c.contains("Too many branches") &&
                !c.contains("Treating indirect jump as call"),
            description + " did not decompile as a complete switch\n" + c);
        require(hasCaseLabel(c, lowCase) && hasCaseLabel(c, highCase),
            description + " lost its case bounds " + lowCase + "-" + highCase + "\n" + c);
        require(c.contains("0xff") || c.contains("255"),
            description + " lost its default result\n" + c);
        requireExactComputedTargets(branchWord, targetWords, description);
    }

    private boolean hasCaseLabel(String c, int value) {
        return c.contains("case " + value + ":") ||
            c.contains("case 0x" + Integer.toHexString(value) + ":");
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

    private void rerunSwitchAnalyzer(String phase) throws Exception {
        MessageLog log = new MessageLog();
        TMS320C28SwitchAnalyzer analyzer = new TMS320C28SwitchAnalyzer();
        require(analyzer.added(currentProgram, new AddressSet(currentProgram.getMemory()),
            monitor, log), "switch analyzer failed during " + phase + ": " + log);
        AutoAnalysisManager.getAnalysisManager(currentProgram).startAnalysis(monitor);
    }

    private void replaceInstructionWord(long word, int replacement) throws Exception {
        Address address = wordAddress(word);
        Instruction instruction = getInstructionAt(address);
        require(instruction != null, "missing instruction to replace at " + address);
        Listing listing = currentProgram.getListing();
        listing.clearCodeUnits(address, instruction.getMaxAddress(), false);
        currentProgram.getMemory().setShort(address, (short) replacement, false);
        require(disassemble(address), "could not disassemble replacement at " + address);
    }

    private String instructionText(long word) {
        Instruction instruction = getInstructionAt(wordAddress(word));
        require(instruction != null, "missing instruction at " + wordAddress(word));
        return normalizeText(instruction.toString()).toLowerCase();
    }

    private String normalizeText(String text) {
        return text.replaceAll("\\s+", " ").trim();
    }

    private List<Address> sortedAddresses(long[] words) {
        List<Address> result = new ArrayList<>();
        for (long word : words) {
            result.add(wordAddress(word));
        }
        Collections.sort(result);
        return result;
    }

    private void requireOwnedNamespaceDescriptor(long branchWord, long[] targetWords,
            String description) {
        Address branch = wordAddress(branchWord);
        Namespace namespace = switchOverrideNamespace(branchWord);
        require(namespace != null, description + " has no jump namespace");
        SymbolTable symbols = currentProgram.getSymbolTable();
        Symbol owner = symbols.getSymbol(SWITCH_OWNER_MARKER, branch, namespace);
        require(owner != null && owner.getSource() == SourceType.ANALYSIS,
            description + " lacks its exact analysis owner marker");
        Symbol switchSymbol = symbols.getSymbol("switch", branch, namespace);
        require(switchSymbol != null && switchSymbol.getSource() == SourceType.USER_DEFINED,
            description + " lacks the standard switch symbol");
        for (int index = 0; index < targetWords.length; index++) {
            Address target = wordAddress(targetWords[index]);
            Symbol caseSymbol = symbols.getSymbol("case_" + index, target, namespace);
            require(caseSymbol != null &&
                    caseSymbol.getSource() == SourceType.USER_DEFINED,
                description + " lacks case_" + index + " at " + target);
        }
        NamespaceSemanticState state = namespaceSemanticState(namespace);
        require(state.children.size() == targetWords.length + 2,
            description + " has unexpected namespace children: " + state.children);
        require(JumpTable.readOverride(namespace, symbols) != null,
            description + " is not readable as a standard JumpTable override");
    }

    private Namespace createStandardSwitchNamespace(Function function, long branchWord) {
        Address branch = wordAddress(branchWord);
        Namespace override = HighFunction.findCreateOverrideSpace(function);
        require(override != null,
            "could not create override namespace for " + branch);
        String name = "jmp_" + branch;
        require(HighFunction.findNamespace(currentProgram.getSymbolTable(), override, name) == null,
            "standard jump namespace already exists before user control at " + branch);
        Namespace namespace = HighFunction.findCreateNamespace(
            currentProgram.getSymbolTable(), override, name);
        require(namespace != null,
            "could not create standard jump namespace for " + branch);
        return namespace;
    }

    private Namespace findDirectChildNamespace(Namespace parent, String name) {
        return HighFunction.findNamespace(currentProgram.getSymbolTable(), parent, name);
    }

    private void removeOwnedSwitchStateForTest(Function function, long branchWord)
            throws Exception {
        Namespace namespace = switchOverrideNamespace(branchWord);
        require(namespace != null && hasExactOwnerMarker(branchWord, SourceType.ANALYSIS),
            "test cleanup cannot prove analyzer ownership at " + wordAddress(branchWord));
        deleteNamespaceForTest(namespace, "analyzer-owned user-control setup");
        removeComputedJumpReferences(wordAddress(branchWord), SourceType.ANALYSIS);
        CreateFunctionCmd.fixupFunctionBody(currentProgram, function, monitor);
    }

    private void deleteNamespaceForTest(Namespace namespace, String description)
            throws Exception {
        SymbolTable symbols = currentProgram.getSymbolTable();
        require(HighFunction.clearNamespace(symbols, namespace),
            "could not clear " + description);
        require(!symbols.getSymbols(namespace).hasNext(),
            description + " retained children after clear");
        Symbol namespaceSymbol = namespace.getSymbol();
        require(namespaceSymbol != null && namespaceSymbol.delete(),
            "could not delete " + description);
    }

    private boolean hasExactOwnerMarker(long branchWord, SourceType source) {
        Namespace namespace = switchOverrideNamespace(branchWord);
        if (namespace == null) {
            return false;
        }
        Symbol marker = currentProgram.getSymbolTable().getSymbol(
            SWITCH_OWNER_MARKER, wordAddress(branchWord), namespace);
        return marker != null && marker.getSource() == source;
    }

    private void removeComputedJumpReferences(Address branch, SourceType source) {
        for (Reference reference :
                currentProgram.getReferenceManager().getReferencesFrom(branch)) {
            if (reference.getReferenceType() == RefType.COMPUTED_JUMP &&
                    reference.getSource() == source) {
                currentProgram.getReferenceManager().delete(reference);
            }
        }
    }

    private int computedJumpCount(Address address, SourceType source) {
        int count = 0;
        for (Reference reference :
                currentProgram.getReferenceManager().getReferencesFrom(address)) {
            if (reference.getReferenceType() == RefType.COMPUTED_JUMP &&
                    reference.getSource() == source) {
                count++;
            }
        }
        return count;
    }

    private boolean hasComputedJumpReference(Address from, Address to, SourceType source) {
        for (Reference reference :
                currentProgram.getReferenceManager().getReferencesFrom(from)) {
            if (reference.getReferenceType() == RefType.COMPUTED_JUMP &&
                    reference.getSource() == source &&
                    reference.getToAddress().equals(to)) {
                return true;
            }
        }
        return false;
    }

    private List<String> computedReferenceSignatures(Address branch) {
        List<String> result = new ArrayList<>();
        for (Reference reference :
                currentProgram.getReferenceManager().getReferencesFrom(branch)) {
            if (reference.getReferenceType() == RefType.COMPUTED_JUMP) {
                result.add(reference.getReferenceType() + "|" + reference.getSource() + "|" +
                    reference.getOperandIndex() + "|" + reference.getToAddress());
            }
        }
        Collections.sort(result);
        return result;
    }

    private NamespaceState namespaceState(Namespace namespace) {
        require(namespace != null, "cannot snapshot a null namespace");
        Symbol namespaceSymbol = namespace.getSymbol();
        require(namespaceSymbol != null, "namespace has no symbol: " + namespace);
        Namespace parent = namespace.getParentNamespace();
        List<String> children = new ArrayList<>();
        SymbolIterator iterator = currentProgram.getSymbolTable().getSymbols(namespace);
        while (iterator.hasNext()) {
            Symbol symbol = iterator.next();
            children.add(symbol.getID() + "|" + symbol.getName() + "|" +
                symbol.getAddress() + "|" + symbol.getSource() + "|" +
                symbol.getSymbolType());
        }
        Collections.sort(children);
        return new NamespaceState(namespace.getID(), namespaceSymbol.getID(),
            parent == null ? -1 : parent.getID(), namespace.getName(),
            namespaceSymbol.getSource(), children);
    }

    private NamespaceSemanticState namespaceSemanticState(Namespace namespace) {
        require(namespace != null, "cannot snapshot a null namespace");
        Symbol namespaceSymbol = namespace.getSymbol();
        require(namespaceSymbol != null, "namespace has no symbol: " + namespace);
        Namespace parent = namespace.getParentNamespace();
        List<String> children = new ArrayList<>();
        SymbolIterator iterator = currentProgram.getSymbolTable().getSymbols(namespace);
        while (iterator.hasNext()) {
            Symbol symbol = iterator.next();
            children.add(symbol.getName() + "|" + symbol.getAddress() + "|" +
                symbol.getSource() + "|" + symbol.getSymbolType());
        }
        Collections.sort(children);
        return new NamespaceSemanticState(parent == null ? -1 : parent.getID(),
            namespace.getName(), namespaceSymbol.getSource(), children);
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
        for (Reference reference : references.getReferencesFrom(address)) {
            if (reference.getReferenceType() == RefType.COMPUTED_JUMP) {
                destinations.add(reference.getToAddress());
            }
        }
        Collections.sort(destinations);
        return destinations;
    }

    private void requireExactComputedTargets(long branchWord, long[] targetWords,
            String description) {
        List<Address> actual = computedJumpDestinations(wordAddress(branchWord));
        List<Address> expected = new ArrayList<>();
        for (long targetWord : targetWords) {
            expected.add(wordAddress(targetWord));
        }
        Collections.sort(actual);
        Collections.sort(expected);
        require(actual.equals(expected),
            description + " computed targets differ: expected=" + expected + " actual=" + actual);
    }

    private Namespace switchOverrideNamespace(long branchWord) {
        Address branch = wordAddress(branchWord);
        Function function = getFunctionContaining(branch);
        if (function == null) {
            return null;
        }
        Namespace override = HighFunction.findOverrideSpace(function);
        return override == null ? null :
            HighFunction.findNamespace(currentProgram.getSymbolTable(), override,
                "jmp_" + branch);
    }

    private void requireOwnedSwitchOverride(long branchWord, boolean expected,
            String description) {
        Namespace namespace = switchOverrideNamespace(branchWord);
        Symbol marker = namespace == null ? null : currentProgram.getSymbolTable()
            .getSymbol(SWITCH_OWNER_MARKER, wordAddress(branchWord), namespace);
        boolean actual = marker != null && marker.getSource() == SourceType.ANALYSIS;
        require(actual == expected,
            description + " analyzer-owned override expectation " + expected +
                " differed at " + wordAddress(branchWord) + " namespace=" + namespace);
    }

    private void requireWords(long startWord, int... expectedWords) throws Exception {
        Address start = wordAddress(startWord);
        int wordSize = start.getAddressSpace().getAddressableUnitSize();
        Memory memory = currentProgram.getMemory();
        for (int index = 0; index < expectedWords.length; index++) {
            Address address = start.add((long) index * wordSize);
            int actual = memory.getShort(address, false) & 0xffff;
            require(actual == (expectedWords[index] & 0xffff),
                "instruction bytes changed at " + address + ": expected 0x" +
                    Integer.toHexString(expectedWords[index] & 0xffff) + " actual 0x" +
                    Integer.toHexString(actual));
        }
    }

    private void requireInstructionText(long word, String expected) {
        Instruction instruction = getInstructionAt(wordAddress(word));
        require(instruction != null, "missing instruction at " + wordAddress(word));
        String actualText = instruction.toString().replaceAll("\\s+", " ").trim()
            .toLowerCase();
        String expectedText = expected.replaceAll("\\s+", " ").trim().toLowerCase();
        require(actualText.equals(expectedText),
            "disassembly text changed at " + wordAddress(word) + ": expected '" +
                expectedText + "' actual '" + actualText + "'");
    }

    private String pcodeRegisterName(Varnode node) {
        if (node == null || !node.getAddress().isRegisterAddress()) {
            return null;
        }
        Register register = currentProgram.getLanguage().getRegister(
            node.getAddress(), node.getSize());
        return register == null ? null : register.getName();
    }

    private Set<String> pcodeRegisters(Instruction instruction) {
        Set<String> result = new HashSet<>();
        for (PcodeOp op : instruction.getPcode()) {
            String output = pcodeRegisterName(op.getOutput());
            if (output != null) {
                result.add(output.toUpperCase());
            }
            for (Varnode input : op.getInputs()) {
                String name = pcodeRegisterName(input);
                if (name != null) {
                    result.add(name.toUpperCase());
                }
            }
        }
        return result;
    }

    private void requireCanonicalSubbPcode(long word) {
        Instruction instruction = getInstructionAt(wordAddress(word));
        require(instruction != null && instruction.getMnemonicString().equalsIgnoreCase("SUBB"),
            "missing canonical SUBB at " + wordAddress(word));
        require(hasPcodeOp(instruction, PcodeOp.INT_SUB),
            "canonical SUBB lacks ordinary-width INT_SUB at " + wordAddress(word));
        Set<String> touched = pcodeRegisters(instruction);
        require(!touched.contains("OVM") && !touched.contains("OVC") &&
                !touched.contains("V"),
            "canonical SUBB retained unsafe overflow state at " + wordAddress(word) +
                ": " + touched);
    }

    private void requireOrdinarySubbPcode(long word) {
        Instruction instruction = getInstructionAt(wordAddress(word));
        require(instruction != null && instruction.getMnemonicString().equalsIgnoreCase("SUBB"),
            "missing ordinary SUBB at " + wordAddress(word));
        Set<String> touched = pcodeRegisters(instruction);
        require(hasPcodeOp(instruction, PcodeOp.INT_SUB) && touched.contains("OVM") &&
                touched.contains("OVC") && touched.contains("V"),
            "near-miss SUBB lost ordinary architectural status behavior at " +
                wordAddress(word) + ": " + touched);
    }

    private void requireOrdinaryIndirectBranch(long word) {
        Instruction instruction = getInstructionAt(wordAddress(word));
        require(instruction != null && instruction.getMnemonicString().equalsIgnoreCase("LB"),
            "missing LB *XAR7 at " + wordAddress(word));
        require(hasPcodeOp(instruction, PcodeOp.BRANCHIND) &&
                !hasPcodeOp(instruction, PcodeOp.CALLIND) &&
                !hasPcodeOp(instruction, PcodeOp.RETURN),
            "LB *XAR7 gained unsafe call/return classification at " + wordAddress(word));
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

    private static final class NamespaceState {
        private final long namespaceId;
        private final long namespaceSymbolId;
        private final long parentId;
        private final String name;
        private final SourceType source;
        private final List<String> children;

        private NamespaceState(long namespaceId, long namespaceSymbolId, long parentId,
                String name, SourceType source, List<String> children) {
            this.namespaceId = namespaceId;
            this.namespaceSymbolId = namespaceSymbolId;
            this.parentId = parentId;
            this.name = name;
            this.source = source;
            this.children = List.copyOf(children);
        }

        @Override
        public boolean equals(Object object) {
            if (!(object instanceof NamespaceState other)) {
                return false;
            }
            return namespaceId == other.namespaceId &&
                namespaceSymbolId == other.namespaceSymbolId &&
                parentId == other.parentId && Objects.equals(name, other.name) &&
                source == other.source && children.equals(other.children);
        }

        @Override
        public int hashCode() {
            return Objects.hash(namespaceId, namespaceSymbolId, parentId, name, source,
                children);
        }

        @Override
        public String toString() {
            return "NamespaceState[id=" + namespaceId + ", symbol=" +
                namespaceSymbolId + ", parent=" + parentId + ", name=" + name +
                ", source=" + source + ", children=" + children + "]";
        }
    }

    private static final class NamespaceSemanticState {
        private final long parentId;
        private final String name;
        private final SourceType source;
        private final List<String> children;

        private NamespaceSemanticState(long parentId, String name, SourceType source,
                List<String> children) {
            this.parentId = parentId;
            this.name = name;
            this.source = source;
            this.children = List.copyOf(children);
        }

        @Override
        public boolean equals(Object object) {
            if (!(object instanceof NamespaceSemanticState other)) {
                return false;
            }
            return parentId == other.parentId && Objects.equals(name, other.name) &&
                source == other.source && children.equals(other.children);
        }

        @Override
        public int hashCode() {
            return Objects.hash(parentId, name, source, children);
        }
    }
}
