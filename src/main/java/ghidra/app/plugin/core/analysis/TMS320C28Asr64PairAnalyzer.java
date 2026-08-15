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
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Selects an exact net-32-bit arithmetic shift for adjacent
 * {@code ASR64 ACC:P,#16; ASR64 ACC:P,#16} compiler schedules.
 * <p>
 * A pair is accepted only when both instructions have exact immediate count
 * sixteen, are adjacent in one function, the first falls through exclusively
 * to the second, neither instruction has alternate/interior ingress, and the
 * second instruction does not read the C/N/Z state written by the first.  The
 * first selected constructor is semantically inert and the second snapshots
 * the original ACC:P to publish the exact final ACC, P, C, N and Z state of a
 * net arithmetic right shift by 32.  Ordinary standalone and rejected ASR64
 * instructions retain the architectural constructor.
 * <p>
 * Context is non-flowing and revalidated on every run.  Stale phases are
 * revoked before redisassembly.
 */
public class TMS320C28Asr64PairAnalyzer extends AbstractAnalyzer {

    private static final String NAME = "TMS320C28 Adjacent ASR64 Pair Analyzer";
    private static final String DESCRIPTION =
        "Exposes exact adjacent ASR64 #16 pairs as one net 32-bit sign extension";
    private static final String PROCESSOR_NAME = "TMS320C28";
    private static final String CONTEXT_NAME = "asr64_pair_phase";
    private static final int FIRST = 1;
    private static final int SECOND = 2;

    public TMS320C28Asr64PairAnalyzer() {
        super(NAME, DESCRIPTION, AnalyzerType.FUNCTION_ANALYZER);
        setPriority(AnalysisPriority.FUNCTION_ANALYSIS.after());
        setDefaultEnablement(true);
    }

    @Override
    public boolean canAnalyze(Program program) {
        return program.getLanguage().getProcessor().equals(
            Processor.findOrPossiblyCreateProcessor(PROCESSOR_NAME));
    }

    @Override
    public void registerOptions(Options options, Program program) {
        // Intentionally finite: no heuristic or firmware-address controls.
    }

    @Override
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor,
            MessageLog log) throws CancelledException {
        ProgramContext context = program.getProgramContext();
        Register phaseContext = context.getRegister(CONTEXT_NAME);
        Register c = program.getLanguage().getRegister("C");
        Register n = program.getLanguage().getRegister("N");
        Register z = program.getLanguage().getRegister("Z");
        if (phaseContext == null || c == null || n == null || z == null) {
            log.appendMsg(NAME, "missing ASR64 phase or C/N/Z register");
            return false;
        }

        Map<Address, Integer> validPhases = new HashMap<>();
        FunctionIterator functions = program.getFunctionManager().getFunctions(true);
        while (functions.hasNext()) {
            monitor.checkCancelled();
            analyzeFunction(program, functions.next(), c, n, z, validPhases, monitor);
        }

        Listing listing = program.getListing();
        List<ContextChange> revocations = new ArrayList<>();
        List<ContextChange> additions = new ArrayList<>();
        InstructionIterator instructions = listing.getInstructions(true);
        while (instructions.hasNext()) {
            monitor.checkCancelled();
            Instruction instruction = instructions.next();
            int tagged = taggedPhase(context, phaseContext, instruction);
            Integer proved = validPhases.get(instruction.getMinAddress());
            int desired = proved != null && isAsr64Immediate16(instruction)
                ? proved.intValue() : 0;
            if (tagged == desired) {
                continue;
            }
            ContextChange change = new ContextChange(
                instruction.getMinAddress(), instruction.getMaxAddress(), desired);
            if (desired == 0) {
                revocations.add(change);
            }
            else {
                additions.add(change);
            }
        }

        AddressSet redisassemble = new AddressSet();
        for (ContextChange change : revocations) {
            changeContext(listing, context, phaseContext, change, redisassemble, log);
            Msg.info(this, "revoked stale ASR64-pair context at " + change.start);
        }
        for (ContextChange change : additions) {
            changeContext(listing, context, phaseContext, change, redisassemble, log);
            Msg.info(this, "proved ASR64-pair phase=" + change.value + " at " +
                change.start);
        }
        if (!redisassemble.isEmpty()) {
            AutoAnalysisManager.getAnalysisManager(program)
                .disassemble(redisassemble, AnalysisPriority.DISASSEMBLY);
        }
        return true;
    }

    private static void analyzeFunction(Program program, Function function, Register c,
            Register n, Register z, Map<Address, Integer> validPhases,
            TaskMonitor monitor) throws CancelledException {
        if (function == null || function.isExternal()) {
            return;
        }
        Listing listing = program.getListing();
        List<Instruction> instructions = new ArrayList<>();
        InstructionIterator iterator = listing.getInstructions(function.getBody(), true);
        while (iterator.hasNext()) {
            monitor.checkCancelled();
            instructions.add(iterator.next());
        }
        if (instructions.size() < 2) {
            return;
        }

        Map<Address, Set<Instruction>> predecessors = buildPredecessors(instructions);
        ReferenceManager references = program.getReferenceManager();
        for (int index = 0; index + 1 < instructions.size();) {
            monitor.checkCancelled();
            Instruction first = instructions.get(index);
            Instruction second = instructions.get(index + 1);
            if (isValidPair(function, first, second, predecessors, references, c, n, z)) {
                validPhases.put(first.getMinAddress(), FIRST);
                validPhases.put(second.getMinAddress(), SECOND);
                index += 2;
            }
            else {
                index++;
            }
        }
    }

    private static Map<Address, Set<Instruction>> buildPredecessors(
            List<Instruction> instructions) {
        Map<Address, Instruction> byAddress = new LinkedHashMap<>();
        Map<Address, Set<Instruction>> result = new HashMap<>();
        for (Instruction instruction : instructions) {
            byAddress.put(instruction.getMinAddress(), instruction);
            result.put(instruction.getMinAddress(), new LinkedHashSet<>());
        }
        for (Instruction instruction : instructions) {
            if (instruction.getFlowType().isCall()) {
                addPredecessor(result, byAddress, instruction,
                    instruction.getFallThrough());
                continue;
            }
            for (Address flow : instruction.getFlows()) {
                addPredecessor(result, byAddress, instruction, flow);
            }
            addPredecessor(result, byAddress, instruction,
                instruction.getFallThrough());
        }
        return result;
    }

    private static void addPredecessor(Map<Address, Set<Instruction>> predecessors,
            Map<Address, Instruction> byAddress, Instruction source, Address target) {
        if (target != null && byAddress.containsKey(target)) {
            predecessors.get(target).add(source);
        }
    }

    private static boolean isValidPair(Function function, Instruction first,
            Instruction second, Map<Address, Set<Instruction>> predecessors,
            ReferenceManager references, Register c, Register n, Register z) {
        if (!isAsr64Immediate16(first) || !isAsr64Immediate16(second)) {
            return false;
        }
        Address expectedSecond;
        try {
            expectedSecond = first.getMaxAddress().addNoWrap(1);
        }
        catch (Exception exception) {
            return false;
        }
        if (!expectedSecond.equals(second.getMinAddress()) ||
            !second.getMinAddress().equals(first.getFallThrough()) ||
            first.getFlows().length != 0 || first.getFlowType().isConditional() ||
            first.getFlowType().isJump() || first.getFlowType().isCall() ||
            first.getFlowType().isTerminal()) {
            return false;
        }

        Set<Instruction> secondPredecessors = predecessors.get(second.getMinAddress());
        if (secondPredecessors == null || secondPredecessors.size() != 1 ||
            !secondPredecessors.contains(first)) {
            return false;
        }
        Set<Instruction> firstPredecessors = predecessors.get(first.getMinAddress());
        if (first.getMinAddress().equals(function.getEntryPoint())) {
            if (firstPredecessors != null && !firstPredecessors.isEmpty()) {
                return false;
            }
        }
        else {
            if (firstPredecessors == null || firstPredecessors.size() != 1) {
                return false;
            }
            Instruction predecessor = firstPredecessors.iterator().next();
            Address expectedFirst;
            try {
                expectedFirst = predecessor.getMaxAddress().addNoWrap(1);
            }
            catch (Exception exception) {
                return false;
            }
            if (!expectedFirst.equals(first.getMinAddress()) ||
                !first.getMinAddress().equals(predecessor.getFallThrough()) ||
                predecessor.getFlows().length != 0 ||
                predecessor.getFlowType().isConditional() ||
                predecessor.getFlowType().isJump() ||
                predecessor.getFlowType().isTerminal()) {
                return false;
            }
        }

        if (hasUnexpectedIngress(first, function, firstPredecessors, references) ||
            hasUnexpectedIngress(second, function, secondPredecessors, references)) {
            return false;
        }
        return !readsRegister(second, c) && !readsRegister(second, n) &&
            !readsRegister(second, z);
    }

    private static boolean hasUnexpectedIngress(Instruction instruction,
            Function function, Set<Instruction> expectedPredecessors,
            ReferenceManager references) {
        Set<Address> expected = new HashSet<>();
        if (expectedPredecessors != null) {
            for (Instruction predecessor : expectedPredecessors) {
                expected.add(predecessor.getMinAddress());
            }
        }
        boolean entry = instruction.getMinAddress().equals(function.getEntryPoint());
        ReferenceIterator incoming = references.getReferencesTo(
            instruction.getMinAddress());
        while (incoming.hasNext()) {
            Reference reference = incoming.next();
            if (!reference.getReferenceType().isFlow()) {
                continue;
            }
            if (expected.contains(reference.getFromAddress())) {
                continue;
            }
            if (entry && reference.getReferenceType().isCall()) {
                continue;
            }
            return true;
        }
        return false;
    }

    private static boolean readsRegister(Instruction instruction, Register register) {
        for (PcodeOp op : instruction.getPcode()) {
            for (Varnode input : op.getInputs()) {
                if (overlapsRegisterVarnode(input, register)) {
                    return true;
                }
            }
        }
        for (Object object : instruction.getInputObjects()) {
            if (object instanceof Register input && overlaps(input, register)) {
                return true;
            }
        }
        return false;
    }

    private static boolean isAsr64Immediate16(Instruction instruction) {
        if (instruction == null || instruction.getMnemonicString() == null ||
            !instruction.getMnemonicString().equalsIgnoreCase("ASR64")) {
            return false;
        }
        boolean acc = false;
        boolean p = false;
        int scalars = 0;
        long value = -1;
        for (int operand = 0; operand < instruction.getNumOperands(); operand++) {
            for (Object object : instruction.getOpObjects(operand)) {
                if (object instanceof Register register) {
                    if (register.getName().equalsIgnoreCase("ACC")) {
                        acc = true;
                    }
                    else if (register.getName().equalsIgnoreCase("P")) {
                        p = true;
                    }
                }
                else if (object instanceof Scalar scalar) {
                    scalars++;
                    value = scalar.getUnsignedValue();
                }
            }
        }
        return acc && p && scalars == 1 && value == 16;
    }

    private static int taggedPhase(ProgramContext context, Register register,
            Instruction instruction) {
        BigInteger value = context.getValue(register, instruction.getMinAddress(), false);
        return value == null ? 0 : value.intValue() & 3;
    }

    private static void changeContext(Listing listing, ProgramContext context,
            Register phaseContext, ContextChange change, AddressSet redisassemble,
            MessageLog log) {
        try {
            listing.clearCodeUnits(change.start, change.end, false);
            context.setValue(phaseContext, change.start, change.end,
                BigInteger.valueOf(change.value));
            redisassemble.add(change.start);
        }
        catch (ContextChangeException exception) {
            log.appendException(exception);
        }
    }

    private static boolean overlapsRegisterVarnode(Varnode node, Register register) {
        if (node == null || !node.isRegister()) {
            return false;
        }
        long nodeStart = node.getAddress().getOffset();
        long nodeEnd = nodeStart + node.getSize();
        long registerStart = register.getAddress().getOffset();
        long registerEnd = registerStart + register.getMinimumByteSize();
        return nodeStart < registerEnd && registerStart < nodeEnd;
    }

    private static boolean overlaps(Register left, Register right) {
        return left.contains(right) || right.contains(left);
    }

    private record ContextChange(Address start, Address end, int value) {
    }
}
