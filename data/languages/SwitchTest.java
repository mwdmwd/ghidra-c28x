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

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }

    @Override
    public void run() throws Exception {
        if (currentProgram.getName().contains("validation")) {
            testCompactValidationFixture();
        }
        else {
            testCompilerFixture();
        }
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
        long highWord = memory.getShort(wordAddress(0x130ad), false) & 0xffffL;
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

        println("SWITCH_VALIDATION_POSITIVE_REFS=4");
        println("SWITCH_VALIDATION_REJECTED=6");
        println("SWITCH_VALIDATION_CASE_RANGE=0x120-0x123");
        println("SWITCH_VALIDATION_BODY_TARGETS=4");
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
        int count = 0;
        ReferenceManager references = currentProgram.getReferenceManager();
        for (Reference reference : references.getReferencesFrom(address, Reference.MNEMONIC)) {
            if (reference.getReferenceType() == RefType.COMPUTED_JUMP) {
                count++;
            }
        }
        return count;
    }

    private boolean isCanonical(Address address, Register context) {
        return BigInteger.ONE.equals(
            currentProgram.getProgramContext().getValue(context, address, false));
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

    private long scalarAt(long wordOffset, int operand) {
        Instruction instruction = getInstructionAt(wordAddress(wordOffset));
        require(instruction != null, "missing fixture instruction at " + wordAddress(wordOffset));
        Scalar scalar = instruction.getScalar(operand);
        require(scalar != null, "missing fixture scalar at " + wordAddress(wordOffset));
        return scalar.getUnsignedValue();
    }
}
