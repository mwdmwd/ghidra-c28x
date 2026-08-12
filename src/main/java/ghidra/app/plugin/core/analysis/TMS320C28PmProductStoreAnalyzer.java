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
 * Selects a direct low-half store for {@code MOV loc16,P} only when the
 * effective decoded product shift is proved to be zero.
 * <p>
 * The ordinary SLEIGH constructor remains the architectural definition: it
 * reads PM and performs the documented signed product shift.  This analyzer
 * merely selects an equivalent non-flowing constructor at an individual MOV
 * when a finite intraprocedural proof establishes the TI C run-time contract.
 * A proof can originate at an exclusively call-entered function boundary, at
 * a dominating explicit SPM definition, or after a completed C call.  Every CFG
 * predecessor is merged, and any disagreement or unmodelled ingress makes the
 * value unknown.  Dynamic PM/ST0 restoration likewise invalidates the proof.
 * <p>
 * Context is revalidated on every run.  Tags on no-longer-proved stores, or on
 * any instruction other than {@code MOV loc16,P}, are revoked before the
 * affected instruction is redisassembled with the ordinary constructor.
 */
public class TMS320C28PmProductStoreAnalyzer extends AbstractAnalyzer {

    private static final String NAME =
        "TMS320C28 Proved No-Shift Product Store Analyzer";
    private static final String DESCRIPTION =
        "Canonicalizes MOV loc16,P only where decoded PM is proved zero";
    private static final String PROCESSOR_NAME = "TMS320C28";
    private static final String CONTEXT_NAME = "pm_store_noshift";

    private static final int BOTTOM = Integer.MIN_VALUE;
    private static final int UNKNOWN = Integer.MAX_VALUE;
    private static final int ZERO_SHIFT = 0;

    public TMS320C28PmProductStoreAnalyzer() {
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
        // The proof is intentionally finite and has no widening options.
    }

    @Override
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor,
            MessageLog log) throws CancelledException {
        ProgramContext context = program.getProgramContext();
        Register canonicalContext = context.getRegister(CONTEXT_NAME);
        Register pm = program.getLanguage().getRegister("PM");
        if (canonicalContext == null || pm == null) {
            log.appendMsg(NAME, "missing SLEIGH PM/canonical context register");
            return false;
        }

        Listing listing = program.getListing();
        Set<Address> validSites = new HashSet<>();
        FunctionIterator functions = program.getFunctionManager().getFunctions(true);
        while (functions.hasNext()) {
            monitor.checkCancelled();
            analyzeFunction(program, functions.next(), pm, validSites, monitor);
        }

        List<Instruction> additions = new ArrayList<>();
        List<Instruction> revocations = new ArrayList<>();
        InstructionIterator instructions = listing.getInstructions(true);
        while (instructions.hasNext()) {
            monitor.checkCancelled();
            Instruction instruction = instructions.next();
            boolean tagged = tagged(context, canonicalContext, instruction);
            boolean valid = validSites.contains(instruction.getMinAddress()) &&
                isProductStore(instruction);
            if (valid && !tagged) {
                additions.add(instruction);
            }
            else if (tagged && !valid) {
                revocations.add(instruction);
            }
        }

        AddressSet redisassemble = new AddressSet();
        // Revoke stale assumptions before publishing new ones.  This matters
        // when analysis has discovered an alternate ingress since the prior run.
        for (Instruction instruction : revocations) {
            Address address = instruction.getMinAddress();
            changeContext(listing, context, canonicalContext, instruction,
                BigInteger.ZERO, redisassemble, log);
            Msg.info(this, "revoked stale PM product-store context at " + address);
        }
        for (Instruction instruction : additions) {
            Address address = instruction.getMinAddress();
            changeContext(listing, context, canonicalContext, instruction,
                BigInteger.ONE, redisassemble, log);
            Msg.info(this, "proved no-shift MOV loc16,P at " + address);
        }

        if (!redisassemble.isEmpty()) {
            AutoAnalysisManager.getAnalysisManager(program)
                .disassemble(redisassemble, AnalysisPriority.DISASSEMBLY);
        }
        return true;
    }

    private static void analyzeFunction(Program program, Function function,
            Register pm, Set<Address> validSites, TaskMonitor monitor)
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

        Address entry = function.getEntryPoint();
        Node entryNode = nodes.get(entry);
        ReferenceManager references = program.getReferenceManager();
        boolean boundaryCall = false;
        boolean boundaryConflict = false;

        for (Node node : nodes.values()) {
            monitor.checkCancelled();
            Set<Address> expectedSources = new HashSet<>();
            for (Node predecessor : node.predecessors) {
                expectedSources.add(predecessor.instruction.getMinAddress());
            }
            ReferenceIterator incoming = references.getReferencesTo(
                node.instruction.getMinAddress());
            while (incoming.hasNext()) {
                Reference reference = incoming.next();
                if (!reference.getReferenceType().isFlow()) {
                    continue;
                }
                Address source = reference.getFromAddress();
                if (expectedSources.contains(source)) {
                    continue;
                }
                if (node == entryNode && reference.getReferenceType().isCall()) {
                    Instruction sourceInstruction = listing.getInstructionAt(source);
                    if (isArchitecturalCallTo(sourceInstruction,
                            node.instruction.getMinAddress())) {
                        boundaryCall = true;
                        continue;
                    }
                    // Shared-return analysis can retype an ordinary branch as
                    // CALL.  That is not a documented TI C function boundary.
                }
                node.alternateIngress = true;
                if (node == entryNode) {
                    boundaryConflict = true;
                }
            }
            // A detached interior block is an implicit ingress even if Ghidra
            // has not materialized a reference to it yet.
            if (node != entryNode && node.predecessors.isEmpty()) {
                node.alternateIngress = true;
            }
        }
        boolean boundaryZero = entryNode != null && boundaryCall && !boundaryConflict;

        Deque<Node> work = new ArrayDeque<>(nodes.values());
        Set<Node> queued = new HashSet<>(nodes.values());
        while (!work.isEmpty()) {
            monitor.checkCancelled();
            Node node = work.removeFirst();
            queued.remove(node);

            // An unproved function entry is a real unknown ingress, not an
            // unreachable lattice bottom.  This prevents an explicit PM
            // definition on a backedge from retroactively proving a store
            // that executes before the definition on the first entry.
            int incoming = node == entryNode
                ? (boundaryZero ? ZERO_SHIFT : UNKNOWN)
                : BOTTOM;
            if (node.alternateIngress) {
                incoming = merge(incoming, UNKNOWN);
            }
            for (Node predecessor : node.predecessors) {
                incoming = merge(incoming, predecessor.outputState);
            }

            int outgoing = transfer(node.instruction, incoming, pm);
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
            if (node.inputState == ZERO_SHIFT && isProductStore(node.instruction)) {
                validSites.add(node.instruction.getMinAddress());
            }
        }
    }

    private static int transfer(Instruction instruction, int incoming, Register pm) {
        Integer explicit = explicitPmShift(instruction, pm);
        if (explicit != null) {
            return explicit.intValue();
        }
        if (isCompletedCall(instruction)) {
            // Table 7-4's raw PM=1 return contract is decoded PM=0 here.
            return ZERO_SHIFT;
        }
        if (writesPm(instruction, pm)) {
            return UNKNOWN;
        }
        return incoming;
    }

    private static Integer explicitPmShift(Instruction instruction, Register pm) {
        if (!isMnemonic(instruction, "SPM")) {
            return null;
        }
        Integer value = null;
        for (PcodeOp op : instruction.getPcode()) {
            if (!exactRegisterVarnode(op.getOutput(), pm)) {
                continue;
            }
            if (value != null || op.getOpcode() != PcodeOp.COPY ||
                op.getNumInputs() != 1 || !op.getInput(0).isConstant()) {
                return null;
            }
            Varnode input = op.getInput(0);
            int bits = input.getSize() * 8;
            if (bits <= 0 || bits > 32) {
                return null;
            }
            long mask = bits == 32 ? 0xffffffffL : (1L << bits) - 1;
            long signed = input.getOffset() & mask;
            long sign = 1L << (bits - 1);
            if ((signed & sign) != 0) {
                signed -= 1L << bits;
            }
            if (signed < -6 || signed > 4) {
                return null;
            }
            // Raw 101 is already decoded by SLEIGH as -4 or +4 according to
            // AMODE.  Both remain exact nonzero states and are never accepted.
            value = Integer.valueOf((int) signed);
        }
        return value;
    }

    private static boolean exactRegisterVarnode(Varnode node, Register register) {
        return node != null && node.isRegister() &&
            node.getAddress().equals(register.getAddress()) &&
            node.getSize() == register.getMinimumByteSize();
    }

    private static boolean isCompletedCall(Instruction instruction) {
        return isArchitecturalCall(instruction) &&
            instruction.getFlowType().isCall() &&
            instruction.getFallThrough() != null;
    }

    private static boolean isArchitecturalCallTo(Instruction instruction,
            Address target) {
        if (!isArchitecturalCall(instruction)) {
            return false;
        }
        for (Address flow : instruction.getFlows()) {
            if (flow.equals(target)) {
                return true;
            }
        }
        return false;
    }

    private static boolean isArchitecturalCall(Instruction instruction) {
        if (instruction == null) {
            return false;
        }
        String mnemonic = instruction.getMnemonicString();
        return mnemonic.equalsIgnoreCase("LCR") ||
            mnemonic.equalsIgnoreCase("LC") ||
            mnemonic.equalsIgnoreCase("FFC");
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
        if (target == null || target == source) {
            if (target == source) {
                source.predecessors.add(source);
                source.successors.add(source);
            }
            return;
        }
        source.successors.add(target);
        target.predecessors.add(source);
    }

    private static boolean isProductStore(Instruction instruction) {
        return isMnemonic(instruction, "MOV") && instruction.getNumOperands() == 2 &&
            isExactRegisterOperand(instruction, 1, "P");
    }

    private static boolean isMnemonic(Instruction instruction, String mnemonic) {
        return instruction != null && instruction.getMnemonicString() != null &&
            instruction.getMnemonicString().toUpperCase(Locale.ROOT).equals(mnemonic);
    }

    private static boolean tagged(ProgramContext context, Register register,
            Instruction instruction) {
        return BigInteger.ONE.equals(context.getValue(register,
            instruction.getMinAddress(), false));
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

    private static boolean writesPm(Instruction instruction, Register pm) {
        if (instruction == null || pm == null) {
            return false;
        }
        for (PcodeOp op : instruction.getPcode()) {
            if (overlapsRegisterVarnode(op.getOutput(), pm)) {
                return true;
            }
        }
        return writesOverlap(instruction, pm);
    }

    private static boolean overlapsRegisterVarnode(Varnode node, Register register) {
        if (node == null || !node.isRegister() || register == null) {
            return false;
        }
        long nodeStart = node.getAddress().getOffset();
        long nodeEnd = nodeStart + node.getSize();
        long registerStart = register.getAddress().getOffset();
        long registerEnd = registerStart + register.getMinimumByteSize();
        return nodeStart < registerEnd && registerStart < nodeEnd;
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
