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
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
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
import ghidra.program.model.lang.OperandType;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Selects branch-free {@code LSRL ACC,T} P-Code only where the effective
 * five-bit T count is an exact, nonzero constant on every ingress.
 * <p>
 * The ordinary constructor remains authoritative for unknown and masked-zero
 * counts.  This analyzer performs a finite intraprocedural data-flow proof:
 * only a full immediate {@code MOV T,#imm} establishes a value; calls and any
 * other write overlapping T invalidate it; predecessor states must agree after
 * the documented T(4:0) mask; and alternate/interior ingress contributes an
 * unknown state.  Only the proved shift instruction receives non-flowing
 * context, so bytes and display remain unchanged.
 * <p>
 * Existing context is revalidated on every run.  Stale or malformed tags are
 * cleared before redisassembly selects the ordinary constructor again.
 */
public class TMS320C28ConstantShiftAnalyzer extends AbstractAnalyzer {

    private static final String NAME = "TMS320C28 Proved Constant-T Shift Analyzer";
    private static final String DESCRIPTION =
        "Removes local CFG from LSRL ACC,T only at proved nonzero constant counts";
    private static final String PROCESSOR_NAME = "TMS320C28";
    private static final String CONTEXT_NAME = "lsrl_t_count";

    private static final int BOTTOM = -1;
    private static final int UNKNOWN = 32;
    private static final int COUNT_MASK = 0x1f;

    public TMS320C28ConstantShiftAnalyzer() {
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
        // Deliberately finite; there are no widening or heuristic options.
    }

    @Override
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor,
            MessageLog log) throws CancelledException {
        ProgramContext context = program.getProgramContext();
        Register countContext = context.getRegister(CONTEXT_NAME);
        Register t = program.getLanguage().getRegister("T");
        if (countContext == null || t == null) {
            log.appendMsg(NAME, "missing SLEIGH T/count context register");
            return false;
        }

        Map<Address, Integer> validCounts = new HashMap<>();
        FunctionIterator functions = program.getFunctionManager().getFunctions(true);
        while (functions.hasNext()) {
            monitor.checkCancelled();
            analyzeFunction(program, functions.next(), t, validCounts, monitor);
        }

        Listing listing = program.getListing();
        List<ContextChange> revocations = new ArrayList<>();
        List<ContextChange> additions = new ArrayList<>();
        InstructionIterator instructions = listing.getInstructions(true);
        while (instructions.hasNext()) {
            monitor.checkCancelled();
            Instruction instruction = instructions.next();
            int taggedCount = taggedCount(context, countContext, instruction);
            Integer proved = validCounts.get(instruction.getMinAddress());
            int desired = proved != null && isLsrlAccT(instruction)
                ? proved.intValue() : 0;
            if (taggedCount == desired) {
                continue;
            }
            ContextChange change = new ContextChange(instruction, desired);
            if (desired == 0) {
                revocations.add(change);
            }
            else {
                additions.add(change);
            }
        }

        AddressSet redisassemble = new AddressSet();
        for (ContextChange change : revocations) {
            changeContext(listing, context, countContext, change, redisassemble, log);
            Msg.info(this, "revoked stale constant-T shift context at " +
                change.instruction.getMinAddress());
        }
        for (ContextChange change : additions) {
            changeContext(listing, context, countContext, change, redisassemble, log);
            Msg.info(this, "proved LSRL ACC,T count=" + change.value + " at " +
                change.instruction.getMinAddress());
        }

        if (!redisassemble.isEmpty()) {
            AutoAnalysisManager.getAnalysisManager(program)
                .disassemble(redisassemble, AnalysisPriority.DISASSEMBLY);
        }
        return true;
    }

    private static void analyzeFunction(Program program, Function function, Register t,
            Map<Address, Integer> validCounts, TaskMonitor monitor)
            throws CancelledException {
        if (function == null || function.isExternal()) {
            return;
        }
        Listing listing = program.getListing();
        LinkedHashMap<Address, Node> nodes = new LinkedHashMap<>();
        InstructionIterator iterator = listing.getInstructions(function.getBody(), true);
        while (iterator.hasNext()) {
            monitor.checkCancelled();
            Instruction instruction = iterator.next();
            nodes.put(instruction.getMinAddress(), new Node(instruction));
        }
        if (nodes.isEmpty()) {
            return;
        }

        for (Node node : nodes.values()) {
            Instruction instruction = node.instruction;
            if (instruction.getFlowType().isCall()) {
                addSuccessor(nodes, node, instruction.getFallThrough());
            }
            else {
                for (Address flow : instruction.getFlows()) {
                    addSuccessor(nodes, node, flow);
                }
                addSuccessor(nodes, node, instruction.getFallThrough());
            }
        }

        Node entry = nodes.get(function.getEntryPoint());
        ReferenceManager references = program.getReferenceManager();
        for (Node node : nodes.values()) {
            monitor.checkCancelled();
            Set<Address> expected = new HashSet<>();
            for (Node predecessor : node.predecessors) {
                expected.add(predecessor.instruction.getMinAddress());
            }
            ReferenceIterator incoming = references.getReferencesTo(
                node.instruction.getMinAddress());
            while (incoming.hasNext()) {
                Reference reference = incoming.next();
                if (reference.getReferenceType().isFlow() &&
                    !expected.contains(reference.getFromAddress())) {
                    // Calls to the function entry still begin with unknown T and
                    // therefore do not create a proof.  Other unexpected flow is
                    // an explicit unknown ingress as well.
                    node.alternateIngress = true;
                }
            }
            if (node != entry && node.predecessors.isEmpty()) {
                node.alternateIngress = true;
            }
        }

        Deque<Node> work = new ArrayDeque<>(nodes.values());
        Set<Node> queued = new HashSet<>(nodes.values());
        while (!work.isEmpty()) {
            monitor.checkCancelled();
            Node node = work.removeFirst();
            queued.remove(node);

            int incoming = node == entry ? UNKNOWN : BOTTOM;
            if (node.alternateIngress) {
                incoming = merge(incoming, UNKNOWN);
            }
            for (Node predecessor : node.predecessors) {
                incoming = merge(incoming, predecessor.outputState);
            }
            int outgoing = transfer(node.instruction, incoming, t);
            if (incoming == node.inputState && outgoing == node.outputState) {
                continue;
            }
            node.inputState = incoming;
            node.outputState = outgoing;
            for (Node successor : node.successors) {
                if (queued.add(successor)) {
                    work.addLast(successor);
                }
            }
        }

        for (Node node : nodes.values()) {
            if (node.inputState > 0 && node.inputState <= COUNT_MASK &&
                isLsrlAccT(node.instruction)) {
                validCounts.put(node.instruction.getMinAddress(), node.inputState);
            }
        }
    }

    private static int transfer(Instruction instruction, int incoming, Register t) {
        Integer exact = exactImmediateTCount(instruction);
        if (exact != null) {
            return exact.intValue();
        }
        if (instruction.getFlowType().isCall() || writesOverlap(instruction, t)) {
            return UNKNOWN;
        }
        return incoming;
    }

    private static Integer exactImmediateTCount(Instruction instruction) {
        if (!isMnemonic(instruction, "MOV") || instruction.getNumOperands() != 2 ||
            !isExactRegisterOperand(instruction, 0, "T")) {
            return null;
        }
        Long value = immediateScalarOperand(instruction, 1);
        if (value == null) {
            return null;
        }
        return Integer.valueOf((int) (value.longValue() & COUNT_MASK));
    }

    private static int merge(int left, int right) {
        if (left == BOTTOM) {
            return right;
        }
        if (right == BOTTOM || left == right) {
            return left;
        }
        return UNKNOWN;
    }

    private static void addSuccessor(Map<Address, Node> nodes, Node source,
            Address address) {
        if (address == null) {
            return;
        }
        Node target = nodes.get(address);
        if (target == null) {
            return;
        }
        source.successors.add(target);
        target.predecessors.add(source);
    }

    private static boolean isLsrlAccT(Instruction instruction) {
        return isMnemonic(instruction, "LSRL") && instruction.getNumOperands() == 2 &&
            isExactRegisterOperand(instruction, 0, "ACC") &&
            isExactRegisterOperand(instruction, 1, "T");
    }

    private static boolean isMnemonic(Instruction instruction, String mnemonic) {
        return instruction != null && instruction.getMnemonicString() != null &&
            instruction.getMnemonicString().toUpperCase(Locale.ROOT).equals(mnemonic);
    }

    private static int taggedCount(ProgramContext context, Register register,
            Instruction instruction) {
        BigInteger value = context.getValue(register, instruction.getMinAddress(), false);
        return value == null ? 0 : value.intValue() & COUNT_MASK;
    }

    private static void changeContext(Listing listing, ProgramContext context,
            Register countContext, ContextChange change, AddressSet redisassemble,
            MessageLog log) {
        try {
            Address start = change.instruction.getMinAddress();
            Address end = change.instruction.getMaxAddress();
            listing.clearCodeUnits(start, end, false);
            context.setValue(countContext, start, end, BigInteger.valueOf(change.value));
            redisassemble.add(start);
        }
        catch (ContextChangeException exception) {
            log.appendException(exception);
        }
    }

    private static boolean writesOverlap(Instruction instruction, Register expected) {
        if (instruction == null || expected == null) {
            return false;
        }
        for (PcodeOp op : instruction.getPcode()) {
            if (overlapsRegisterVarnode(op.getOutput(), expected)) {
                return true;
            }
        }
        for (Object object : instruction.getResultObjects()) {
            if (object instanceof Register result && overlaps(result, expected)) {
                return true;
            }
        }
        return false;
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

    private record ContextChange(Instruction instruction, int value) {
    }

    private static final class Node {
        final Instruction instruction;
        final Set<Node> predecessors = new LinkedHashSet<>();
        final Set<Node> successors = new LinkedHashSet<>();
        boolean alternateIngress;
        int inputState = BOTTOM;
        int outputState = BOTTOM;

        Node(Instruction instruction) {
            this.instruction = instruction;
        }
    }
}
