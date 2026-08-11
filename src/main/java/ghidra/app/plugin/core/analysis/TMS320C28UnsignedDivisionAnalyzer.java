/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.app.plugin.core.analysis;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Selects canonical quotient/remainder P-Code only for a completely proved
 * {@code RPT #31; SUBCUL ACC,loc32} unsigned division.
 * <p>
 * Ordinary SUBCUL is a single restoring step and remains modeled exactly as
 * such.  This analyzer summarizes the repeated form only when a finite,
 * straight-line predecessor slice proves all of the architectural premises:
 * ACC's last definition is zero, P's last definition is a 32-bit snapshot,
 * the repeat count is 31, and the divisor is an unchanged nonzero full-width
 * register.  The proof slice must have contiguous fall-through and exclusive
 * ingress after its first instruction.  Memory divisors are deliberately
 * rejected, so no store alias can invalidate the divisor snapshot.
 * <p>
 * The selected SLEIGH constructor emits unsigned INT_DIV/INT_REM and the
 * documented final C/N/Z/RPTC state without changing instruction bytes or
 * display.  If any premise disappears, a previously selected site is revoked
 * and redisassembled with the ordinary restoring semantics.
 */
public class TMS320C28UnsignedDivisionAnalyzer extends AbstractAnalyzer {

    private static final String NAME = "TMS320C28 Unsigned Division Idiom Analyzer";
    private static final String DESCRIPTION =
        "Canonicalizes proved 32-step RPT #31/SUBCUL unsigned division";
    private static final String PROCESSOR_NAME = "TMS320C28";
    private static final String CONTEXT_NAME = "subcul_div32";
    // Bounded far enough to retain one proved divisor across the firmware's
    // straight-line run of twelve delay conversions; every interior instruction
    // is still checked for flow, ingress, and relevant register writes.
    private static final int MAX_SETUP_INSTRUCTIONS = 96;

    public TMS320C28UnsignedDivisionAnalyzer() {
        super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
        setPriority(AnalysisPriority.DISASSEMBLY.after());
        setDefaultEnablement(true);
    }

    @Override
    public boolean canAnalyze(Program program) {
        return program.getLanguage().getProcessor().equals(
            Processor.findOrPossiblyCreateProcessor(PROCESSOR_NAME));
    }

    @Override
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor,
            MessageLog log) throws CancelledException {
        ProgramContext context = program.getProgramContext();
        Register canonicalContext = context.getRegister(CONTEXT_NAME);
        if (canonicalContext == null) {
            log.appendMsg(NAME, "missing SLEIGH context register " + CONTEXT_NAME);
            return false;
        }

        Listing listing = program.getListing();
        List<DivisionMatch> matches = new ArrayList<>();
        Set<Address> validSites = new HashSet<>();
        InstructionIterator instructions = listing.getInstructions(true);
        while (instructions.hasNext()) {
            monitor.checkCancelled();
            Instruction instruction = instructions.next();
            if (!isMnemonic(instruction, "SUBCUL")) {
                continue;
            }
            DivisionMatch match = recover(program, instruction, monitor);
            if (match != null) {
                matches.add(match);
                validSites.add(instruction.getMinAddress());
            }
        }

        List<Instruction> revocations = new ArrayList<>();
        instructions = listing.getInstructions(true);
        while (instructions.hasNext()) {
            monitor.checkCancelled();
            Instruction instruction = instructions.next();
            if (tagged(context, canonicalContext, instruction) &&
                !validSites.contains(instruction.getMinAddress())) {
                revocations.add(instruction);
            }
        }

        AddressSet redisassemble = new AddressSet();
        for (DivisionMatch match : matches) {
            Instruction instruction = listing.getInstructionAt(match.subculAddress);
            if (instruction == null || tagged(context, canonicalContext, instruction)) {
                continue;
            }
            changeContext(listing, context, canonicalContext, instruction,
                BigInteger.ONE, redisassemble, log);
            Msg.info(this, "recognized full-width unsigned SUBCUL division at " +
                match.subculAddress + " divisor=" + match.divisorName +
                " setupInstructions=" + match.instructionCount);
        }
        for (Instruction instruction : revocations) {
            Address address = instruction.getMinAddress();
            changeContext(listing, context, canonicalContext, instruction,
                BigInteger.ZERO, redisassemble, log);
            Msg.info(this, "revoked unproved SUBCUL division at " + address);
        }

        if (!redisassemble.isEmpty()) {
            AutoAnalysisManager.getAnalysisManager(program)
                .disassemble(redisassemble, AnalysisPriority.DISASSEMBLY);
        }
        return true;
    }

    private static void changeContext(Listing listing, ProgramContext context,
            Register canonicalContext, Instruction instruction, BigInteger value,
            AddressSet redisassemble, MessageLog log) {
        try {
            Address start = instruction.getMinAddress();
            Address end = instruction.getMaxAddress();
            listing.clearCodeUnits(start, end, false);
            context.setValue(canonicalContext, start, end, value);
            redisassemble.add(start);
        }
        catch (ContextChangeException exception) {
            log.appendException(exception);
        }
    }

    private static DivisionMatch recover(Program program, Instruction subcul,
            TaskMonitor monitor) throws CancelledException {
        if (!isMnemonic(subcul, "SUBCUL") ||
            !isExactRegisterOperand(subcul, 0, "ACC")) {
            return null;
        }
        Register divisor = exactRegisterOperand(subcul, 1);
        if (!OperandType.isRegister(subcul.getOperandType(1)) ||
            !allowedDivisor(divisor)) {
            return null; // rejects memory operands and ACC/P aliases
        }

        Instruction rpt = contiguousPrevious(subcul);
        if (!isImmediateRepeat31(rpt)) {
            return null;
        }

        Register acc = program.getLanguage().getRegister("ACC");
        Register product = program.getLanguage().getRegister("P");
        if (acc == null || product == null) {
            return null;
        }

        Instruction accZero = null;
        Instruction productSnapshot = null;
        Instruction divisorDefinition = null;
        Instruction nonzeroRoot = null;
        Instruction current = contiguousPrevious(rpt);
        int examined = 0;
        while (current != null && examined++ < MAX_SETUP_INSTRUCTIONS) {
            monitor.checkCancelled();
            if (accZero == null && writesOverlap(current, acc)) {
                if (!isZeroAccumulator(current)) {
                    return null;
                }
                accZero = current;
            }
            if (productSnapshot == null && writesOverlap(current, product)) {
                if (!isProductSnapshot(current)) {
                    return null;
                }
                productSnapshot = current;
            }
            if (divisorDefinition == null && writesOverlap(current, divisor)) {
                NonzeroProof proof = proveNonzeroDivisor(program, current, divisor,
                    monitor);
                if (proof == null) {
                    return null;
                }
                divisorDefinition = current;
                nonzeroRoot = proof.root;
            }
            if (accZero != null && productSnapshot != null &&
                divisorDefinition != null) {
                break;
            }
            current = contiguousPrevious(current);
        }
        if (accZero == null || productSnapshot == null || divisorDefinition == null ||
            nonzeroRoot == null) {
            return null;
        }

        Instruction first = earliest(accZero, productSnapshot, nonzeroRoot);
        List<Instruction> slice = contiguousSlice(first, subcul,
            MAX_SETUP_INSTRUCTIONS + 3);
        if (slice == null || !slice.contains(rpt) || !slice.contains(accZero) ||
            !slice.contains(productSnapshot) || !slice.contains(divisorDefinition)) {
            return null;
        }
        if (!straightLine(slice) || !exclusiveInteriorIngress(program, slice)) {
            return null;
        }

        // Last-definition scans above prove no later write to ACC, P, or the
        // divisor.  Check explicitly as a reviewable invariant as well.
        if (writtenBetween(slice, accZero, subcul, acc) ||
            writtenBetween(slice, productSnapshot, subcul, product) ||
            writtenBetween(slice, divisorDefinition, subcul, divisor)) {
            return null;
        }

        return new DivisionMatch(subcul.getMinAddress(), divisor.getName(), slice.size());
    }

    private static boolean isImmediateRepeat31(Instruction instruction) {
        if (!isMnemonic(instruction, "RPT") || instruction.getNumOperands() != 1) {
            return false;
        }
        Long count = immediateScalarOperand(instruction, 0);
        return count != null && count.longValue() == 31;
    }

    private static boolean isZeroAccumulator(Instruction instruction) {
        if (!isMnemonic(instruction, "MOVB") ||
            !isExactRegisterOperand(instruction, 0, "ACC")) {
            return false;
        }
        Long value = immediateScalarOperand(instruction, 1);
        return value != null && value.longValue() == 0;
    }

    private static boolean isProductSnapshot(Instruction instruction) {
        if (!isMnemonic(instruction, "MOVL") ||
            !isExactRegisterOperand(instruction, 0, "P") ||
            instruction.getNumOperands() < 2) {
            return false;
        }
        Register source = exactRegisterOperand(instruction, 1);
        return source == null || !source.getName().equalsIgnoreCase("P");
    }

    private static NonzeroProof proveNonzeroDivisor(Program program,
            Instruction definition, Register divisor, TaskMonitor monitor)
            throws CancelledException {
        if (!isMnemonic(definition, "MOVL") ||
            !isExactRegisterOperand(definition, 0, divisor.getName()) ||
            definition.getNumOperands() < 2) {
            return null;
        }

        Long immediate = immediateScalarOperand(definition, 1);
        if (immediate != null) {
            return immediate.longValue() != 0 ? new NonzeroProof(definition) : null;
        }

        Register source = exactRegisterOperand(definition, 1);
        if (!OperandType.isRegister(definition.getOperandType(1)) || source == null ||
            !source.getName().equalsIgnoreCase("ACC")) {
            return null;
        }

        Register acc = program.getLanguage().getRegister("ACC");
        Instruction current = contiguousPrevious(definition);
        for (int count = 0; current != null && count < MAX_SETUP_INSTRUCTIONS; count++) {
            monitor.checkCancelled();
            if (writesOverlap(current, acc)) {
                if (forcesAccumulatorNonzero(current)) {
                    return new NonzeroProof(current);
                }
                return null;
            }
            current = contiguousPrevious(current);
        }
        return null;
    }

    private static boolean forcesAccumulatorNonzero(Instruction instruction) {
        if (isMnemonic(instruction, "MOVB") &&
            isExactRegisterOperand(instruction, 0, "ACC")) {
            Long value = immediateScalarOperand(instruction, 1);
            return value != null && value.longValue() != 0;
        }
        String mnemonic = instruction.getMnemonicString().toUpperCase(Locale.ROOT);
        if (!(mnemonic.equals("ORB") || mnemonic.equals("OR"))) {
            return false;
        }
        Register destination = exactRegisterOperand(instruction, 0);
        if (destination == null) {
            return false;
        }
        String destinationName = destination.getName().toUpperCase(Locale.ROOT);
        if (!(destinationName.equals("ACC") || destinationName.equals("AL") ||
            destinationName.equals("AH"))) {
            return false;
        }
        Long mask = immediateScalarOperand(instruction, 1);
        return mask != null && mask.longValue() != 0;
    }

    private static boolean allowedDivisor(Register divisor) {
        if (divisor == null) {
            return false;
        }
        String name = divisor.getName().toUpperCase(Locale.ROOT);
        if (name.equals("XT")) {
            return true;
        }
        return name.matches("XAR[0-7]");
    }

    private static List<Instruction> contiguousSlice(Instruction first,
            Instruction last, int maximum) {
        List<Instruction> result = new ArrayList<>();
        Instruction current = first;
        for (int count = 0; current != null && count < maximum; count++) {
            result.add(current);
            if (current.getMinAddress().equals(last.getMinAddress())) {
                return result;
            }
            current = contiguousNext(current);
        }
        return null;
    }

    private static boolean straightLine(List<Instruction> slice) {
        for (int i = 0; i + 1 < slice.size(); i++) {
            Instruction instruction = slice.get(i);
            Instruction next = slice.get(i + 1);
            if (instruction.getFlowType().isCall() || instruction.getFlowType().isJump() ||
                instruction.getFlowType().isTerminal() || instruction.getFlows().length != 0 ||
                instruction.getFallThrough() == null ||
                !instruction.getFallThrough().equals(next.getMinAddress())) {
                return false;
            }
        }
        return true;
    }

    private static boolean exclusiveInteriorIngress(Program program,
            List<Instruction> slice) {
        Set<Address> addresses = new HashSet<>();
        for (Instruction instruction : slice) {
            addresses.add(instruction.getMinAddress());
        }
        for (int i = 1; i < slice.size(); i++) {
            Address address = slice.get(i).getMinAddress();
            if (program.getFunctionManager().getFunctionAt(address) != null) {
                return false;
            }
            ReferenceIterator references = program.getReferenceManager()
                .getReferencesTo(slice.get(i).getMinAddress());
            while (references.hasNext()) {
                Reference reference = references.next();
                if (reference.getReferenceType().isFlow() &&
                    !addresses.contains(reference.getFromAddress())) {
                    return false;
                }
            }
        }
        return true;
    }

    private static boolean writtenBetween(List<Instruction> slice, Instruction start,
            Instruction end, Register register) {
        boolean after = false;
        for (Instruction instruction : slice) {
            if (instruction.getMinAddress().equals(start.getMinAddress())) {
                after = true;
                continue;
            }
            if (instruction.getMinAddress().equals(end.getMinAddress())) {
                return false;
            }
            if (after && writesOverlap(instruction, register)) {
                return true;
            }
        }
        return true;
    }

    private static Instruction earliest(Instruction... instructions) {
        Instruction earliest = instructions[0];
        for (Instruction instruction : instructions) {
            if (instruction.getMinAddress().compareTo(earliest.getMinAddress()) < 0) {
                earliest = instruction;
            }
        }
        return earliest;
    }

    private static boolean tagged(ProgramContext context, Register register,
            Instruction instruction) {
        return BigInteger.ONE.equals(context.getValue(register,
            instruction.getMinAddress(), false));
    }

    private static boolean writesOverlap(Instruction instruction, Register expected) {
        if (instruction == null || expected == null) {
            return false;
        }
        for (Object object : instruction.getResultObjects()) {
            if (object instanceof Register result && overlaps(result, expected)) {
                return true;
            }
        }
        if (instruction.getNumOperands() > 0) {
            Register destination = exactRegisterOperand(instruction, 0);
            if (destination != null && overlaps(destination, expected)) {
                return true;
            }
        }
        return false;
    }

    private static boolean overlaps(Register left, Register right) {
        return left.contains(right) || right.contains(left);
    }

    private static Register exactRegisterOperand(Instruction instruction, int operand) {
        if (instruction == null || operand < 0 || operand >= instruction.getNumOperands()) {
            return null;
        }
        Register register = instruction.getRegister(operand);
        if (register != null) {
            return register;
        }
        Object[] objects = instruction.getOpObjects(operand);
        Register only = null;
        for (Object object : objects) {
            if (object instanceof Register objectRegister) {
                if (only != null && !only.equals(objectRegister)) {
                    return null;
                }
                only = objectRegister;
            }
            else if (!(object instanceof Scalar)) {
                return null;
            }
        }
        return only;
    }

    private static boolean isExactRegisterOperand(Instruction instruction, int operand,
            String registerName) {
        Register register = exactRegisterOperand(instruction, operand);
        return register != null && register.getName().equalsIgnoreCase(registerName);
    }


    private static Long immediateScalarOperand(Instruction instruction, int operand) {
        if (instruction == null || operand < 0 || operand >= instruction.getNumOperands()) {
            return null;
        }
        int type = instruction.getOperandType(operand);
        if (!OperandType.isScalar(type) || OperandType.isAddress(type) ||
            OperandType.isIndirect(type) || OperandType.isDynamic(type)) {
            return null;
        }
        return scalarOperand(instruction, operand);
    }

    private static Long scalarOperand(Instruction instruction, int operand) {
        if (instruction == null || operand < 0 || operand >= instruction.getNumOperands()) {
            return null;
        }
        Object[] objects = instruction.getOpObjects(operand);
        Long result = null;
        for (Object object : objects) {
            if (object instanceof Scalar scalar) {
                if (result != null) {
                    return null;
                }
                result = scalar.getUnsignedValue();
            }
        }
        return result;
    }

    private static boolean scalarOperand(Instruction instruction, int operand,
            long value) {
        Long scalar = scalarOperand(instruction, operand);
        return scalar != null && scalar.longValue() == value;
    }

    private static boolean isMnemonic(Instruction instruction, String mnemonic) {
        return instruction != null &&
            instruction.getMnemonicString().equalsIgnoreCase(mnemonic);
    }

    private static Instruction contiguousPrevious(Instruction instruction) {
        if (instruction == null) {
            return null;
        }
        Instruction previous = instruction.getPrevious();
        return previous != null && previous.getMaxAddress().next()
            .equals(instruction.getMinAddress()) ? previous : null;
    }

    private static Instruction contiguousNext(Instruction instruction) {
        if (instruction == null) {
            return null;
        }
        Instruction next = instruction.getNext();
        return next != null && instruction.getMaxAddress().next()
            .equals(next.getMinAddress()) ? next : null;
    }

    private static final class NonzeroProof {
        private final Instruction root;

        private NonzeroProof(Instruction root) {
            this.root = root;
        }
    }

    private static final class DivisionMatch {
        private final Address subculAddress;
        private final String divisorName;
        private final int instructionCount;

        private DivisionMatch(Address subculAddress, String divisorName,
                int instructionCount) {
            this.subculAddress = subculAddress;
            this.divisorName = divisorName;
            this.instructionCount = instructionCount;
        }
    }
}
