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
 * Selects an exact OVM=0 form of {@code ADDU ACC,loc16} only where a finite
 * data-flow proof establishes the TI C run-time return contract.
 * <p>
 * Raw instruction P-Code remains fully architectural everywhere else.  A zero
 * fact can originate at an exclusively C-call-entered function boundary, at
 * an explicit {@code CLRC OVM}, or after a completed call whose unique callee
 * uses the prototype model appropriate to its architectural call mechanism.
 * {@code SETC OVM} produces a known-one state; arbitrary ST0/OVM writes and
 * unresolved or ambiguous calls produce unknown.  Every CFG predecessor must
 * agree, and alternate ingress invalidates the proof.
 * <p>
 * The context is revalidated on every run.  Stale tags are revoked before the
 * affected instruction is redisassembled with the ordinary OVM-sensitive
 * constructor.
 */
public class TMS320C28OvmReturnAnalyzer extends AbstractAnalyzer {

    private static final String NAME = "TMS320C28 TI C OVM Return Analyzer";
    private static final String DESCRIPTION =
        "Removes unreachable OVM saturation only at proved TI C OVM=0 states";
    private static final String PROCESSOR_NAME = "TMS320C28";
    private static final String CONTEXT_NAME = "ovm_zero";

    private static final int BOTTOM = -1;
    private static final int ZERO = 0;
    private static final int ONE = 1;
    private static final int UNKNOWN = 2;

    private static final String DEFAULT_CONVENTION = "__stdcall";
    private static final String LC_CONVENTION = "__lc";
    private static final String FFC_CONVENTION = "__ffc";

    public TMS320C28OvmReturnAnalyzer() {
        super(NAME, DESCRIPTION, AnalyzerType.FUNCTION_ANALYZER);
        // Run after ordinary function/call-mechanism analysis has selected
        // __lc/__ffc where those mechanisms are actually proved.
        setPriority(AnalysisPriority.FUNCTION_ANALYSIS.after().after());
        setDefaultEnablement(true);
    }

    @Override
    public boolean canAnalyze(Program program) {
        return program.getLanguage().getProcessor().equals(
            Processor.findOrPossiblyCreateProcessor(PROCESSOR_NAME));
    }

    @Override
    public void registerOptions(Options options, Program program) {
        // Deliberately finite; there are no widening or address-list options.
    }

    @Override
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor,
            MessageLog log) throws CancelledException {
        ProgramContext context = program.getProgramContext();
        Register canonicalContext = context.getRegister(CONTEXT_NAME);
        Register ovm = program.getLanguage().getRegister("OVM");
        if (canonicalContext == null || ovm == null) {
            log.appendMsg(NAME, "missing SLEIGH OVM/canonical context register");
            return false;
        }

        Set<Address> validSites = new HashSet<>();
        FunctionIterator functions = program.getFunctionManager().getFunctions(true);
        while (functions.hasNext()) {
            monitor.checkCancelled();
            analyzeFunction(program, functions.next(), ovm, validSites, monitor);
        }

        Listing listing = program.getListing();
        List<Instruction> additions = new ArrayList<>();
        List<Instruction> revocations = new ArrayList<>();
        InstructionIterator instructions = listing.getInstructions(true);
        while (instructions.hasNext()) {
            monitor.checkCancelled();
            Instruction instruction = instructions.next();
            boolean tagged = tagged(context, canonicalContext, instruction);
            boolean valid = validSites.contains(instruction.getMinAddress()) &&
                isAdduAccumulator(instruction);
            if (valid && !tagged) {
                additions.add(instruction);
            }
            else if (tagged && !valid) {
                revocations.add(instruction);
            }
        }

        AddressSet redisassemble = new AddressSet();
        for (Instruction instruction : revocations) {
            Address address = instruction.getMinAddress();
            changeContext(listing, context, canonicalContext, instruction,
                BigInteger.ZERO, redisassemble, log);
            Msg.info(this, "revoked stale OVM=0 arithmetic context at " + address);
        }
        for (Instruction instruction : additions) {
            Address address = instruction.getMinAddress();
            changeContext(listing, context, canonicalContext, instruction,
                BigInteger.ONE, redisassemble, log);
            Msg.info(this, "proved OVM=0 ADDU at " + address);
        }

        if (!redisassemble.isEmpty()) {
            AutoAnalysisManager.getAnalysisManager(program)
                .disassemble(redisassemble, AnalysisPriority.DISASSEMBLY);
        }
        return true;
    }

    private static void analyzeFunction(Program program, Function function,
            Register ovm, Set<Address> validSites, TaskMonitor monitor)
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
                    Function callee = provedCallee(program, sourceInstruction);
                    if (callee != null && callee.getEntryPoint().equals(entry)) {
                        boundaryCall = true;
                        continue;
                    }
                }
                node.alternateIngress = true;
                if (node == entryNode) {
                    boundaryConflict = true;
                }
            }
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

            int incoming = node == entryNode ? (boundaryZero ? ZERO : UNKNOWN) : BOTTOM;
            if (node.alternateIngress) {
                incoming = merge(incoming, UNKNOWN);
            }
            for (Node predecessor : node.predecessors) {
                incoming = merge(incoming, predecessor.outputState);
            }

            int outgoing = transfer(program, node.instruction, incoming, ovm);
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
            if (node.inputState == ZERO && isAdduAccumulator(node.instruction)) {
                validSites.add(node.instruction.getMinAddress());
            }
        }
    }

    private static int transfer(Program program, Instruction instruction, int incoming,
            Register ovm) {
        Integer explicit = explicitOvm(instruction);
        if (explicit != null) {
            return explicit.intValue();
        }
        if (isArchitecturalCall(instruction) && instruction.getFlowType().isCall() &&
            instruction.getFallThrough() != null) {
            // A call kills ST0 in the ordinary prototype model.  Only a unique
            // callee with the mechanism-appropriate TI C prototype restores
            // the documented OVM=0 return fact.
            return provedCallee(program, instruction) != null ? ZERO : UNKNOWN;
        }
        if (writesOvm(instruction, ovm)) {
            return UNKNOWN;
        }
        return incoming;
    }

    private static Integer explicitOvm(Instruction instruction) {
        if (instruction == null || instruction.getNumOperands() == 0) {
            return null;
        }
        boolean clear = isMnemonic(instruction, "CLRC");
        boolean set = isMnemonic(instruction, "SETC");
        if (!clear && !set) {
            return null;
        }

        boolean selected = false;
        Scalar scalar = instruction.getScalar(0);
        if (scalar != null && (scalar.getUnsignedValue() & 0x2L) != 0) {
            selected = true;
        }
        String representation = instruction.getDefaultOperandRepresentation(0);
        if (representation != null) {
            for (String token : representation.toUpperCase(Locale.ROOT).split("[^A-Z0-9_]+")) {
                if ("OVM".equals(token)) {
                    selected = true;
                }
            }
        }
        if (!selected) {
            return null;
        }
        return Integer.valueOf(clear ? ZERO : ONE);
    }

    /** Return the unique callee only when its selected model matches the opcode. */
    private static Function provedCallee(Program program, Instruction instruction) {
        if (!isArchitecturalCall(instruction) || !instruction.getFlowType().isCall()) {
            return null;
        }

        Set<Address> targets = new LinkedHashSet<>();
        for (Address flow : instruction.getFlows()) {
            targets.add(flow);
        }
        for (Reference reference : program.getReferenceManager().getReferencesFrom(
            instruction.getMinAddress())) {
            if (reference.getReferenceType().isCall()) {
                targets.add(reference.getToAddress());
            }
        }
        if (targets.size() != 1) {
            return null;
        }

        Function callee = program.getFunctionManager().getFunctionAt(targets.iterator().next());
        if (callee == null || !prototypeMatches(instruction, callee)) {
            return null;
        }
        return callee;
    }

    private static boolean prototypeMatches(Instruction instruction, Function callee) {
        String mnemonic = instruction.getMnemonicString().toUpperCase(Locale.ROOT);
        String convention = callee.getCallingConventionName();
        if ("LC".equals(mnemonic)) {
            return LC_CONVENTION.equals(convention);
        }
        if ("FFC".equals(mnemonic)) {
            return FFC_CONVENTION.equals(convention);
        }
        if (!"LCR".equals(mnemonic)) {
            return false;
        }
        return convention == null || callee.hasUnknownCallingConventionName() ||
            Function.DEFAULT_CALLING_CONVENTION_STRING.equals(convention) ||
            DEFAULT_CONVENTION.equals(convention);
    }

    private static boolean isArchitecturalCall(Instruction instruction) {
        if (instruction == null || instruction.getMnemonicString() == null) {
            return false;
        }
        String mnemonic = instruction.getMnemonicString().toUpperCase(Locale.ROOT);
        return "LCR".equals(mnemonic) || "LC".equals(mnemonic) || "FFC".equals(mnemonic);
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

    private static boolean isAdduAccumulator(Instruction instruction) {
        return isMnemonic(instruction, "ADDU") && instruction.getNumOperands() == 2 &&
            isExactRegisterOperand(instruction, 0, "ACC");
    }

    private static boolean isMnemonic(Instruction instruction, String mnemonic) {
        return instruction != null && instruction.getMnemonicString() != null &&
            instruction.getMnemonicString().equalsIgnoreCase(mnemonic);
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

    private static boolean writesOvm(Instruction instruction, Register ovm) {
        if (instruction == null || ovm == null) {
            return false;
        }
        for (PcodeOp op : instruction.getPcode()) {
            if (overlapsRegisterVarnode(op.getOutput(), ovm)) {
                return true;
            }
        }
        return writesOverlap(instruction, ovm);
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
