// Focused regression for proved constant-T shifts and paired ASR64 idioms.
//@category TMS320C28

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

public class ShiftIdiomTest extends GhidraScript {
    private static final String[] COMPILER_T_FUNCTIONS = {
        "shift_t_div2", "shift_t_div4",
    };
    private static final int[] COMPILER_T_COUNTS = { 31, 30 };
    private static final String[] MANUAL_T_POSITIVES = {
        "shift_t_direct_one", "shift_t_direct_max", "shift_t_direct_sixteen",
        "shift_t_equal_merge", "shift_t_redefined_after_clobber",
    };
    private static final int[] MANUAL_T_COUNTS = { 1, 31, 16, 1, 7 };
    private static final String[] MANUAL_T_NEGATIVES = {
        "shift_t_near_call_clobber", "shift_t_near_conflicting_merge",
        "shift_t_near_zero", "shift_t_near_masked_zero",
        "shift_t_near_dynamic", "shift_t_near_partial_write",
        "shift_t_near_value_clobber", "shift_t_near_alternate_ingress",
    };

    private static final String[] COMPILER_PAIR_FUNCTIONS = {
        "shift_sign_extend_value", "shift_sign_extend_multiply",
        "shift_add_sign_extended_product",
    };
    private static final String[] MANUAL_PAIR_POSITIVES = {
        "shift_pair_direct", "shift_pair_after_impy",
    };
    private static final String[] MANUAL_PAIR_NEGATIVES = {
        "shift_pair_near_standalone", "shift_pair_near_first_count",
        "shift_pair_near_second_count", "shift_pair_near_separated",
        "shift_pair_near_second_ingress", "shift_pair_near_first_ingress",
        "shift_pair_near_flag_observer", "shift_pair_near_conflicting_rejoin",
    };

    private Listing listing;
    private FunctionManager functions;
    private Register countContext;
    private Register pairContext;
    private Register t;
    private Register acc;
    private Register p;
    private Register c;
    private Register n;
    private Register z;
    private final Map<String, Address> fixtureAddresses = new HashMap<>();

    @Override
    public void run() throws Exception {
        listing = currentProgram.getListing();
        functions = currentProgram.getFunctionManager();
        countContext = currentProgram.getProgramContext().getRegister("lsrl_t_count");
        pairContext = currentProgram.getProgramContext().getRegister("asr64_pair_phase");
        t = currentProgram.getLanguage().getRegister("T");
        acc = currentProgram.getLanguage().getRegister("ACC");
        p = currentProgram.getLanguage().getRegister("P");
        c = currentProgram.getLanguage().getRegister("C");
        n = currentProgram.getLanguage().getRegister("N");
        z = currentProgram.getLanguage().getRegister("Z");
        require(countContext != null, "missing lsrl_t_count context");
        require(pairContext != null, "missing asr64_pair_phase context");
        require(t != null && acc != null && p != null && c != null && n != null && z != null,
            "missing architectural shift register");

        String kind = parseFixtureArguments();
        if (kind.equals("compiler")) {
            auditCompiler();
            println("SHIFT_PROGRAM_PASS=" + currentProgram.getName());
        }
        else if (kind.equals("validation")) {
            auditManual();
            println("SHIFT_PROGRAM_PASS=validation");
        }
        else {
            throw new AssertionError("unrecognized shift fixture kind " + kind);
        }
    }

    private void auditCompiler() throws Exception {
        Set<Address> expectedT = auditTPositives(
            COMPILER_T_FUNCTIONS, COMPILER_T_COUNTS);
        Map<Address, Integer> expectedPairs = auditPairPositives(
            COMPILER_PAIR_FUNCTIONS);
        requireTContextOnlyOn(expectedT);
        requirePairContextOnlyOn(expectedPairs);

        DecompInterface decompiler = new DecompInterface();
        require(decompiler.openProgram(currentProgram), "failed to open decompiler");
        int unreachable = 0;
        int signExtensions = 0;
        try {
            for (String name : COMPILER_T_FUNCTIONS) {
                Function function = function(name);
                DecompileResults result = decompiler.decompileFunction(function, 30, monitor);
                require(result.decompileCompleted() && result.getDecompiledFunction() != null,
                    name + " failed to decompile: " + result.getErrorMessage());
                String decompiled = result.getDecompiledFunction().getC();
                require(!decompiled.contains("in_T") && !decompiled.contains("extraout_T"),
                    name + " still exposes T state:\n" + decompiled);
                String message = result.getErrorMessage();
                if (message != null && message.contains("Removing unreachable block")) {
                    unreachable++;
                }
            }
            for (String name : COMPILER_PAIR_FUNCTIONS) {
                Function function = function(name);
                DecompileResults result = decompiler.decompileFunction(function, 30, monitor);
                require(result.decompileCompleted() && result.getDecompiledFunction() != null,
                    name + " failed to decompile: " + result.getErrorMessage());
                String decompiled = result.getDecompiledFunction().getC();
                String upper = decompiled.toUpperCase(Locale.ROOT);
                require(!upper.contains(">> 0X10") && !upper.contains(">> 16") &&
                    !upper.contains("& 0XFFFF"),
                    name + " retained nested 16-bit shift/mask reconstruction:\n" + decompiled);
                if (name.equals("shift_add_sign_extended_product")) {
                    // ADDUL/ADDCL remains honestly split, especially under OVM.
                    // Its CONCAT/CARRY shape is allowed; the pair itself must be
                    // visible as an ordinary signed bit-31 extension.
                    require(upper.contains(">> 0X1F") || upper.contains(">> 31"),
                        name + " lost the signed 32-to-64 extension:\n" + decompiled);
                }
                else {
                    require(!upper.contains("CONCAT"),
                        name + " retained CONCAT reconstruction:\n" + decompiled);
                    require(upper.contains("LONGLONG") || upper.contains("LONG LONG"),
                        name + " did not expose a 64-bit signed result:\n" + decompiled);
                }
                signExtensions++;
                println("SHIFT_PAIR_DECOMP_" + name.toUpperCase(Locale.ROOT) + "=" +
                    decompiled.replaceAll("\\s+", " ").trim());
            }
        }
        finally {
            decompiler.dispose();
        }
        require(unreachable == 0, "constant-T compiler functions retained unreachable blocks");
        println("SHIFT_COMPILER_DIRECT_SITES=" + expectedT.size());
        println("SHIFT_COMPILER_UNREACHABLE_BLOCKS=" + unreachable);
        println("SHIFT_PAIR_COMPILER_PAIRS=" + (expectedPairs.size() / 2));
        println("SHIFT_PAIR_SIGN_EXTENSION_DECOMPILATIONS=" + signExtensions);
    }

    private void auditManual() throws Exception {
        Set<Address> expectedT = auditTPositives(
            MANUAL_T_POSITIVES, MANUAL_T_COUNTS);
        for (String name : MANUAL_T_NEGATIVES) {
            Instruction shift;
            if (name.equals("shift_t_near_alternate_ingress")) {
                shift = listing.getInstructionAt(address("shift_t_alternate_target"));
                require(shift != null && isLsrlAccT(shift),
                    "alternate target no longer names LSRL ACC,T");
            }
            else {
                Function function = function(name);
                List<Instruction> shifts = lsrlInstructions(function);
                require(shifts.size() == 1, name + " must contain one LSRL ACC,T");
                shift = shifts.get(0);
            }
            require(taggedCount(shift) == 0,
                name + " was unsafely tagged with count " + taggedCount(shift));
            requireGenericTShiftPcode(shift, name);
            requireLsrlBytesAndDisplay(shift, name);
        }

        Map<Address, Integer> expectedPairs = auditPairPositives(
            MANUAL_PAIR_POSITIVES);
        for (String name : MANUAL_PAIR_NEGATIVES) {
            Function function = function(name);
            List<Instruction> shifts = asr64Instructions(function);
            require(!shifts.isEmpty(), name + " must contain ASR64");
            for (Instruction shift : shifts) {
                require(taggedPairPhase(shift) == 0,
                    name + " was unsafely assigned pair phase " + taggedPairPhase(shift));
                requireGenericAsr64Pcode(shift, name);
                requireAsr64DisplayAndKnownBytes(shift, name);
            }
        }

        requireTContextOnlyOn(expectedT);
        requirePairContextOnlyOn(expectedPairs);
        requireTStaleContextRevoked();
        requirePairStaleContextRevoked();
        println("SHIFT_MANUAL_DIRECT_SITES=" + expectedT.size());
        println("SHIFT_MANUAL_NEAR_MISSES=" + MANUAL_T_NEGATIVES.length);
        println("SHIFT_PAIR_MANUAL_PAIRS=" + (expectedPairs.size() / 2));
        println("SHIFT_PAIR_MANUAL_NEAR_MISSES=" + MANUAL_PAIR_NEGATIVES.length);
        println("SHIFT_STALE_CONTEXT_REVOKED=2");
        println("SHIFT_PAIR_STALE_CONTEXT_REVOKED=2");
    }

    private Set<Address> auditTPositives(String[] names, int[] counts)
            throws Exception {
        require(names.length == counts.length, "T fixture/count mismatch");
        Set<Address> expected = new HashSet<>();
        for (int index = 0; index < names.length; index++) {
            String name = names[index];
            Function function = function(name);
            List<Instruction> shifts = lsrlInstructions(function);
            require(shifts.size() == 1, name + " must contain one LSRL ACC,T");
            Instruction shift = shifts.get(0);
            require(taggedCount(shift) == counts[index],
                name + " expected count " + counts[index] +
                " but got " + taggedCount(shift));
            requireDirectTShiftPcode(shift, name);
            requireLsrlBytesAndDisplay(shift, name);
            expected.add(shift.getMinAddress());
        }
        return expected;
    }

    private Map<Address, Integer> auditPairPositives(String[] names) throws Exception {
        Map<Address, Integer> expected = new LinkedHashMap<>();
        for (String name : names) {
            Function function = function(name);
            List<Instruction> shifts = asr64Instructions(function);
            require(shifts.size() == 2, name + " must contain exactly two ASR64 instructions");
            Instruction first = shifts.get(0);
            Instruction second = shifts.get(1);
            require(first.getMaxAddress().add(1).equals(second.getMinAddress()),
                name + " ASR64 pair is no longer adjacent");
            require(taggedPairPhase(first) == 1 && taggedPairPhase(second) == 2,
                name + " pair phases are " + taggedPairPhase(first) + "/" +
                taggedPairPhase(second));
            requirePairFirstPcode(first, name);
            requirePairSecondPcode(second, name);
            requireAsr64Immediate16BytesAndDisplay(first, name + " first");
            requireAsr64Immediate16BytesAndDisplay(second, name + " second");
            expected.put(first.getMinAddress(), 1);
            expected.put(second.getMinAddress(), 2);
        }
        return expected;
    }

    private void requireTContextOnlyOn(Set<Address> expected) throws Exception {
        Set<Address> actual = new HashSet<>();
        int nonShift = 0;
        InstructionIterator iterator = listing.getInstructions(true);
        while (iterator.hasNext()) {
            monitor.checkCancelled();
            Instruction instruction = iterator.next();
            int count = taggedCount(instruction);
            if (count == 0) {
                continue;
            }
            actual.add(instruction.getMinAddress());
            if (!isLsrlAccT(instruction)) {
                nonShift++;
            }
            requireDirectTShiftPcode(instruction,
                "context-tagged site " + instruction.getMinAddress());
        }
        require(actual.equals(expected),
            "unexpected constant-T context sites: expected=" + expected + " actual=" + actual);
        require(nonShift == 0, "constant-T context leaked onto non-LSRL instructions");
        println("SHIFT_CONTEXT_ON_NON_LSRL=" + nonShift);
    }

    private void requirePairContextOnlyOn(Map<Address, Integer> expected)
            throws Exception {
        Map<Address, Integer> actual = new LinkedHashMap<>();
        int nonAsr64 = 0;
        InstructionIterator iterator = listing.getInstructions(true);
        while (iterator.hasNext()) {
            monitor.checkCancelled();
            Instruction instruction = iterator.next();
            int phase = taggedPairPhase(instruction);
            if (phase == 0) {
                continue;
            }
            actual.put(instruction.getMinAddress(), phase);
            if (!instruction.getMnemonicString().equalsIgnoreCase("ASR64")) {
                nonAsr64++;
            }
            if (phase == 1) {
                requirePairFirstPcode(instruction,
                    "context-tagged first " + instruction.getMinAddress());
            }
            else if (phase == 2) {
                requirePairSecondPcode(instruction,
                    "context-tagged second " + instruction.getMinAddress());
            }
            else {
                throw new AssertionError("invalid ASR64 pair phase " + phase);
            }
        }
        require(actual.equals(expected),
            "unexpected ASR64 pair context: expected=" + expected + " actual=" + actual);
        require(nonAsr64 == 0, "ASR64 pair context leaked onto non-ASR64 instructions");
        println("SHIFT_PAIR_CONTEXT_ON_NON_ASR64=" + nonAsr64);
    }

    private void requireTStaleContextRevoked() throws Exception {
        Instruction zero = listing.getInstructionAt(address("shift_t_stale_zero"));
        Instruction nonshift = listing.getInstructionAt(address("shift_t_stale_nonshift"));
        require(zero != null && isLsrlAccT(zero),
            "stale-zero label no longer names LSRL ACC,T");
        require(nonshift != null && nonshift.getMnemonicString().equalsIgnoreCase("NOP"),
            "stale-nonshift label no longer names NOP");
        require(taggedCount(zero) == 0 && taggedCount(nonshift) == 0,
            "stale constant-T context was not revoked");
        requireGenericTShiftPcode(zero, "stale zero shift");
        Memory memory = currentProgram.getMemory();
        require(readWord(memory, zero.getMinAddress()) == 0x5622,
            "LSRL bytes changed during context revocation");
        require(readWord(memory, nonshift.getMinAddress()) == 0x7700,
            "NOP bytes changed during context revocation");
        require(normalize(zero.toString()).equals("LSRLACC,T"),
            "LSRL display changed: " + zero);
        require(normalize(nonshift.toString()).equals("NOP"),
            "NOP display changed: " + nonshift);
    }

    private void requirePairStaleContextRevoked() throws Exception {
        Instruction first = listing.getInstructionAt(address("shift_pair_stale_first"));
        Instruction second = listing.getInstructionAt(address("shift_pair_stale_second"));
        require(first != null && second != null &&
            first.getMnemonicString().equalsIgnoreCase("ASR64") &&
            second.getMnemonicString().equalsIgnoreCase("ASR64"),
            "stale pair labels no longer name ASR64 instructions");
        require(taggedPairPhase(first) == 0 && taggedPairPhase(second) == 0,
            "stale ASR64 pair context was not revoked");
        require(readWord(currentProgram.getMemory(), first.getMinAddress()) == 0x568f,
            "stale first ASR64 bytes changed");
        require(readWord(currentProgram.getMemory(), second.getMinAddress()) == 0x568e,
            "stale second ASR64 bytes changed");
        requireGenericAsr64Pcode(first, "stale first ASR64");
        requireGenericAsr64Pcode(second, "stale second ASR64");
        require(normalize(first.toString()).equals("ASR64ACC:P,0X10"),
            "stale first ASR64 display changed: " + first);
        require(normalize(second.toString()).equals("ASR64ACC:P,0XF"),
            "stale second ASR64 display changed: " + second);
    }

    private void requireDirectTShiftPcode(Instruction instruction, String where) {
        boolean localFlow = false;
        boolean tReference = false;
        for (PcodeOp op : instruction.getPcode()) {
            if (op.getOpcode() == PcodeOp.BRANCH || op.getOpcode() == PcodeOp.CBRANCH) {
                localFlow = true;
            }
            if (registerReference(op.getOutput(), t)) {
                tReference = true;
            }
            for (Varnode input : op.getInputs()) {
                if (registerReference(input, t)) {
                    tReference = true;
                }
            }
        }
        require(!localFlow, where + " direct form retained instruction-local flow");
        require(!tReference, where + " direct form still references T");
    }

    private void requireGenericTShiftPcode(Instruction instruction, String where) {
        boolean localFlow = false;
        boolean tReference = false;
        for (PcodeOp op : instruction.getPcode()) {
            if (op.getOpcode() == PcodeOp.BRANCH || op.getOpcode() == PcodeOp.CBRANCH) {
                localFlow = true;
            }
            if (registerReference(op.getOutput(), t)) {
                tReference = true;
            }
            for (Varnode input : op.getInputs()) {
                if (registerReference(input, t)) {
                    tReference = true;
                }
            }
        }
        require(localFlow && tReference,
            where + " no longer retains ordinary variable-count P-Code");
    }

    private void requirePairFirstPcode(Instruction instruction, String where) {
        require(instruction.getPcode().length == 0,
            where + " first ASR64 phase must be semantically inert");
    }

    private void requirePairSecondPcode(Instruction instruction, String where) {
        boolean localFlow = false;
        boolean readsAcc = false;
        boolean readsP = false;
        boolean writesAcc = false;
        boolean writesP = false;
        boolean writesC = false;
        boolean writesN = false;
        boolean writesZ = false;
        for (PcodeOp op : instruction.getPcode()) {
            if (op.getOpcode() == PcodeOp.BRANCH || op.getOpcode() == PcodeOp.CBRANCH) {
                localFlow = true;
            }
            Varnode output = op.getOutput();
            writesAcc |= registerReference(output, acc);
            writesP |= registerReference(output, p);
            writesC |= registerReference(output, c);
            writesN |= registerReference(output, n);
            writesZ |= registerReference(output, z);
            for (Varnode input : op.getInputs()) {
                readsAcc |= registerReference(input, acc);
                readsP |= registerReference(input, p);
            }
        }
        require(!localFlow, where + " second ASR64 phase retained local flow");
        require(readsAcc && readsP, where + " second ASR64 lost original ACC:P snapshots");
        require(writesAcc && writesP && writesC && writesN && writesZ,
            where + " second ASR64 did not publish complete ACC:P/C/N/Z state");
    }

    private void requireGenericAsr64Pcode(Instruction instruction, String where) {
        require(instruction.getPcode().length > 0,
            where + " ordinary ASR64 became semantically inert");
        boolean shift = false;
        boolean writesAcc = false;
        boolean writesP = false;
        for (PcodeOp op : instruction.getPcode()) {
            shift |= op.getOpcode() == PcodeOp.INT_SRIGHT;
            writesAcc |= registerReference(op.getOutput(), acc);
            writesP |= registerReference(op.getOutput(), p);
        }
        require(shift && writesAcc && writesP,
            where + " ordinary ASR64 lost architectural shift/write P-Code");
    }

    private boolean registerReference(Varnode node, Register target) {
        if (node == null || !node.isRegister()) {
            return false;
        }
        long nodeStart = node.getAddress().getOffset();
        long nodeEnd = nodeStart + node.getSize();
        long targetStart = target.getAddress().getOffset();
        long targetEnd = targetStart + target.getMinimumByteSize();
        return nodeStart < targetEnd && targetStart < nodeEnd;
    }

    private void requireLsrlBytesAndDisplay(Instruction shift, String where)
            throws Exception {
        require(readWord(currentProgram.getMemory(), shift.getMinAddress()) == 0x5622,
            where + " LSRL bytes changed");
        require(normalize(shift.toString()).equals("LSRLACC,T"),
            where + " display changed: " + shift);
    }

    private void requireAsr64Immediate16BytesAndDisplay(Instruction shift, String where)
            throws Exception {
        require(readWord(currentProgram.getMemory(), shift.getMinAddress()) == 0x568f,
            where + " ASR64 #16 bytes changed");
        require(normalize(shift.toString()).equals("ASR64ACC:P,0X10"),
            where + " ASR64 #16 display changed: " + shift);
    }

    private void requireAsr64DisplayAndKnownBytes(Instruction shift, String where)
            throws Exception {
        int word = readWord(currentProgram.getMemory(), shift.getMinAddress());
        require(word >= 0x5680 && word <= 0x568f,
            where + " ASR64 immediate bytes changed: 0x" + Integer.toHexString(word));
        require(normalize(shift.toString()).startsWith("ASR64ACC:P,0X"),
            where + " ASR64 display changed: " + shift);
    }

    private int readWord(Memory memory, Address address) throws Exception {
        int low = memory.getByte(address) & 0xff;
        int high = memory.getByte(address.add(1)) & 0xff;
        return low | (high << 8);
    }

    private int taggedCount(Instruction instruction) {
        BigInteger value = currentProgram.getProgramContext().getValue(
            countContext, instruction.getMinAddress(), false);
        return value == null ? 0 : value.intValue() & 0x1f;
    }

    private int taggedPairPhase(Instruction instruction) {
        BigInteger value = currentProgram.getProgramContext().getValue(
            pairContext, instruction.getMinAddress(), false);
        return value == null ? 0 : value.intValue() & 3;
    }

    private List<Instruction> lsrlInstructions(Function function) throws Exception {
        List<Instruction> result = new ArrayList<>();
        InstructionIterator iterator = listing.getInstructions(function.getBody(), true);
        while (iterator.hasNext()) {
            monitor.checkCancelled();
            Instruction instruction = iterator.next();
            if (isLsrlAccT(instruction)) {
                result.add(instruction);
            }
        }
        return result;
    }

    private List<Instruction> asr64Instructions(Function function) throws Exception {
        List<Instruction> result = new ArrayList<>();
        InstructionIterator iterator = listing.getInstructions(function.getBody(), true);
        while (iterator.hasNext()) {
            monitor.checkCancelled();
            Instruction instruction = iterator.next();
            if (instruction.getMnemonicString().equalsIgnoreCase("ASR64")) {
                result.add(instruction);
            }
        }
        return result;
    }

    private boolean isLsrlAccT(Instruction instruction) {
        if (instruction == null || !instruction.getMnemonicString().equalsIgnoreCase("LSRL") ||
            instruction.getNumOperands() != 2) {
            return false;
        }
        Register destination = instruction.getRegister(0);
        Register source = instruction.getRegister(1);
        return destination != null && source != null &&
            destination.getName().equalsIgnoreCase("ACC") &&
            source.getName().equalsIgnoreCase("T");
    }

    private Function function(String name) {
        Address address = address(name);
        Function function = functions.getFunctionAt(address);
        require(function != null, "missing function " + name + " at " + address);
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
            String name = argument.substring(0, equals);
            Address address = toAddr(argument.substring(equals + 1));
            require(address != null, "invalid fixture address " + argument);
            fixtureAddresses.put(name, address);
        }
        return arguments[0];
    }

    private Address address(String name) {
        Address address = fixtureAddresses.get(name);
        require(address != null, "missing fixture address " + name);
        return address;
    }

    private String normalize(String text) {
        return text.replaceAll("\\s+", "").toUpperCase(Locale.ROOT);
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
