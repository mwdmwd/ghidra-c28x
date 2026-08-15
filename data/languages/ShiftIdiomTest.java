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
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

public class ShiftIdiomTest extends GhidraScript {
    private static final String[] COMPILER_FUNCTIONS = {
        "shift_t_div2", "shift_t_div4",
    };
    private static final String[] MANUAL_POSITIVES = {
        "shift_t_direct_one", "shift_t_direct_max", "shift_t_direct_sixteen",
        "shift_t_equal_merge", "shift_t_redefined_after_clobber",
    };
    private static final int[] MANUAL_COUNTS = { 1, 31, 16, 1, 7 };
    private static final String[] MANUAL_NEGATIVES = {
        "shift_t_near_call_clobber", "shift_t_near_conflicting_merge",
        "shift_t_near_zero", "shift_t_near_masked_zero",
        "shift_t_near_dynamic", "shift_t_near_partial_write",
        "shift_t_near_value_clobber", "shift_t_near_alternate_ingress",
    };

    private Listing listing;
    private FunctionManager functions;
    private Register countContext;
    private Register t;
    private final Map<String, Address> fixtureAddresses = new HashMap<>();

    @Override
    public void run() throws Exception {
        listing = currentProgram.getListing();
        functions = currentProgram.getFunctionManager();
        countContext = currentProgram.getProgramContext().getRegister("lsrl_t_count");
        t = currentProgram.getLanguage().getRegister("T");
        require(countContext != null, "missing lsrl_t_count context");
        require(t != null, "missing T register");

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
        Set<Address> expected = new HashSet<>();
        int[] counts = { 31, 30 };
        for (int index = 0; index < COMPILER_FUNCTIONS.length; index++) {
            String name = COMPILER_FUNCTIONS[index];
            Function function = function(name);
            List<Instruction> shifts = lsrlInstructions(function);
            require(shifts.size() == 1, name + " must contain one LSRL ACC,T");
            Instruction shift = shifts.get(0);
            require(taggedCount(shift) == counts[index],
                name + " expected count " + counts[index] + " but got " + taggedCount(shift));
            requireDirectPcode(shift, name);
            requireBytesAndDisplay(shift, name);
            expected.add(shift.getMinAddress());
        }
        requireContextOnlyOn(expected);

        DecompInterface decompiler = new DecompInterface();
        require(decompiler.openProgram(currentProgram), "failed to open decompiler");
        int unreachable = 0;
        try {
            for (String name : COMPILER_FUNCTIONS) {
                Function function = function(name);
                DecompileResults result = decompiler.decompileFunction(function, 30, monitor);
                require(result.decompileCompleted() && result.getDecompiledFunction() != null,
                    name + " failed to decompile: " + result.getErrorMessage());
                String c = result.getDecompiledFunction().getC();
                require(!c.contains("in_T") && !c.contains("extraout_T"),
                    name + " still exposes T state:\n" + c);
                String message = result.getErrorMessage();
                if (message != null && message.contains("Removing unreachable block")) {
                    unreachable++;
                }
            }
        }
        finally {
            decompiler.dispose();
        }
        require(unreachable == 0, "constant-T compiler functions retained unreachable blocks");
        println("SHIFT_COMPILER_DIRECT_SITES=" + expected.size());
        println("SHIFT_COMPILER_UNREACHABLE_BLOCKS=" + unreachable);
    }

    private void auditManual() throws Exception {
        Set<Address> expected = new HashSet<>();
        for (int index = 0; index < MANUAL_POSITIVES.length; index++) {
            String name = MANUAL_POSITIVES[index];
            Function function = function(name);
            List<Instruction> shifts = lsrlInstructions(function);
            require(shifts.size() == 1, name + " must contain one LSRL ACC,T");
            Instruction shift = shifts.get(0);
            require(taggedCount(shift) == MANUAL_COUNTS[index],
                name + " expected count " + MANUAL_COUNTS[index] +
                " but got " + taggedCount(shift));
            requireDirectPcode(shift, name);
            requireBytesAndDisplay(shift, name);
            expected.add(shift.getMinAddress());
        }
        for (String name : MANUAL_NEGATIVES) {
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
            requireGenericPcode(shift, name);
            requireBytesAndDisplay(shift, name);
        }
        requireContextOnlyOn(expected);
        requireStaleContextRevoked();
        println("SHIFT_MANUAL_DIRECT_SITES=" + expected.size());
        println("SHIFT_MANUAL_NEAR_MISSES=" + MANUAL_NEGATIVES.length);
        println("SHIFT_STALE_CONTEXT_REVOKED=2");
    }

    private void requireContextOnlyOn(Set<Address> expected) throws Exception {
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
            requireDirectPcode(instruction,
                "context-tagged site " + instruction.getMinAddress());
        }
        require(actual.equals(expected),
            "unexpected constant-T context sites: expected=" + expected + " actual=" + actual);
        require(nonShift == 0, "constant-T context leaked onto non-LSRL instructions");
        println("SHIFT_CONTEXT_ON_NON_LSRL=" + nonShift);
    }

    private void requireStaleContextRevoked() throws Exception {
        Instruction zero = listing.getInstructionAt(address("shift_t_stale_zero"));
        Instruction nonshift = listing.getInstructionAt(address("shift_t_stale_nonshift"));
        require(zero != null && isLsrlAccT(zero),
            "stale-zero label no longer names LSRL ACC,T");
        require(nonshift != null && nonshift.getMnemonicString().equalsIgnoreCase("NOP"),
            "stale-nonshift label no longer names NOP");
        require(taggedCount(zero) == 0 && taggedCount(nonshift) == 0,
            "stale constant-T context was not revoked");
        requireGenericPcode(zero, "stale zero shift");
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

    private void requireDirectPcode(Instruction instruction, String where) {
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

    private void requireGenericPcode(Instruction instruction, String where) {
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

    private void requireBytesAndDisplay(Instruction shift, String where) throws Exception {
        require(readWord(currentProgram.getMemory(), shift.getMinAddress()) == 0x5622,
            where + " LSRL bytes changed");
        require(normalize(shift.toString()).equals("LSRLACC,T"),
            where + " display changed: " + shift);
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
