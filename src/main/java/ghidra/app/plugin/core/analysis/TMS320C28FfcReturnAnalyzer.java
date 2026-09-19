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
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Reclassifies the terminal {@code LB *XAR7} of a narrowly proven fast-function
 * helper as a return.
 * <p>
 * The C28x {@code FFC XAR7,dest} instruction stores its return address in XAR7;
 * TI documents {@code LB *XAR7} as the corresponding return sequence.  The opcode is
 * nevertheless also the ordinary computed branch used by switch tables.  This
 * analyzer therefore changes no global calling convention and does not match
 * an untagged branch.  It requires all of the following finite evidence:
 * <ul>
 *   <li>one or more decoded FFC calls target the helper entry,</li>
 *   <li>every incoming flow reference to the entry is one of those FFC calls,</li>
 *   <li>there is no fall-through into the entry or external ingress into its body,</li>
 *   <li>the control-flow closure contains at most 128 instructions and its
 *       only reachable exits are {@code LB *XAR7}, and</li>
 *   <li>no intervening instruction writes any part of XAR7.</li>
 * </ul>
 * The closure permits direct branches, rejoins, and internal loops; it does not
 * prove termination. Calls, computed successors, unknown instructions, and
 * instruction-flow overrides fail closed.
 * <p>
 * Adapted from ghidra-tms320c28x c5824a91b2f0f90b8a856832e61641f8b39f2511.
 * All proven exits receive local SLEIGH context selecting
 * RETURN P-Code.  Ordinary indirect branches and switch-canonicalized LBs
 * retain their existing semantics.
 */
public class TMS320C28FfcReturnAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "TMS320C28 FFC Return Analyzer";
	private static final String DESCRIPTION =
		"Recognizes exclusive FFC helpers returning through an untouched XAR7";
	private static final String PROCESSOR_NAME = "TMS320C28";
	private static final String RETURN_CONTEXT_NAME = "ffc_return";
	private static final String SWITCH_CONTEXT_NAME = "switch_canonical";
	private static final int MAX_HELPER_INSTRUCTIONS = 128;

	public TMS320C28FfcReturnAnalyzer() {
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
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		ProgramContext context = program.getProgramContext();
		Register returnContext = context.getRegister(RETURN_CONTEXT_NAME);
		Register switchContext = context.getRegister(SWITCH_CONTEXT_NAME);
		if (returnContext == null || switchContext == null) {
			log.appendMsg(NAME, "missing SLEIGH context register " +
				(returnContext == null ? RETURN_CONTEXT_NAME : SWITCH_CONTEXT_NAME));
			return false;
		}

		Listing listing = program.getListing();
		Map<Address, List<Instruction>> callersByTarget = recoverFfcCallers(listing, monitor);
		List<FfcHelper> matches = new ArrayList<>();
		Set<Address> validReturns = new HashSet<>();
		for (Map.Entry<Address, List<Instruction>> entry : callersByTarget.entrySet()) {
			monitor.checkCancelled();
			FfcHelper helper = recoverHelper(program, entry.getKey(), entry.getValue(),
				switchContext, monitor);
			if (helper != null) {
				matches.add(helper);
				validReturns.addAll(helper.returnAddresses);
			}
		}

		List<Instruction> revocations = new ArrayList<>();
		InstructionIterator taggedInstructions = listing.getInstructions(true);
		while (taggedInstructions.hasNext()) {
			monitor.checkCancelled();
			Instruction instruction = taggedInstructions.next();
			if (BigInteger.ONE.equals(context.getValue(returnContext,
				instruction.getMinAddress(), false)) && !validReturns.contains(instruction.getMinAddress())) {
				revocations.add(instruction);
			}
		}

		AddressSet redisassemble = new AddressSet();
		for (FfcHelper helper : matches) {
			for (Address returnAddress : helper.returnAddresses) {
				Instruction terminal = listing.getInstructionAt(returnAddress);
				if (terminal == null || BigInteger.ONE.equals(context.getValue(returnContext,
					returnAddress, false))) {
					continue;
				}
				if (!changeContext(program, terminal, returnContext, BigInteger.ONE,
					redisassemble, monitor, log)) continue;
				Msg.info(this, "recognized FFC helper return at " + returnAddress +
					" entry=" + helper.entryAddress + " callers=" + helper.callerCount +
					" instructions=" + helper.instructionCount +
					" returns=" + helper.returnAddresses.size());
			}
		}
		for (Instruction terminal : revocations) {
			Address address = terminal.getMinAddress();
			if (!changeContext(program, terminal, returnContext, BigInteger.ZERO,
				redisassemble, monitor, log)) continue;
			Msg.info(this, "revoked unproven FFC helper return at " + address);
		}

		if (!redisassemble.isEmpty()) {
			AutoAnalysisManager.getAnalysisManager(program)
				.disassemble(redisassemble, AnalysisPriority.DISASSEMBLY);
		}
		return true;
	}

	private static boolean changeContext(Program program, Instruction instruction,
			Register register, BigInteger value, AddressSet redisassemble,
			TaskMonitor monitor, MessageLog log) {
		Address start = instruction.getMinAddress();
		Address end = instruction.getMaxAddress();
		FlowOverride flowOverride = instruction.getFlowOverride();
		boolean fallOverridden = instruction.isFallThroughOverridden();
		Address fallThrough = instruction.getFallThrough();
		int lengthOverride = instruction.isLengthOverridden() ? instruction.getLength() : 0;
		List<SavedReference> references = new ArrayList<>();
		for (Reference ref : program.getReferenceManager().getReferencesFrom(start)) {
			if (ref.isMemoryReference() && ref.getSource() != SourceType.DEFAULT) {
				references.add(new SavedReference(ref.getToAddress(), ref.getReferenceType(),
					ref.getSource(), ref.getOperandIndex(), ref.isPrimary()));
			}
		}
		try {
			program.getListing().clearCodeUnits(start, end, false);
			program.getProgramContext().setValue(register, start, end, value);
			// Restore instruction overrides immediately, before any queued analyzer can
			// inspect the replacement. Never let an override hide an unproven CFG path.
			if (flowOverride != FlowOverride.NONE || fallOverridden || lengthOverride != 0) {
				if (!new DisassembleCommand(start, null, false).applyTo(program, monitor)) {
					log.appendMsg(NAME, "could not redisassemble overridden instruction at " + start);
					return false;
				}
				Instruction restored = program.getListing().getInstructionAt(start);
				restored.setFlowOverride(flowOverride);
				if (fallOverridden) restored.setFallThrough(fallThrough);
				if (lengthOverride != 0) restored.setLengthOverride(lengthOverride);
			}
			redisassemble.add(start);
			return true;
		}
		catch (ContextChangeException | ghidra.program.model.util.CodeUnitInsertionException exception) {
			log.appendException(exception);
			return false;
		}
		finally {
			for (SavedReference saved : references) {
				Reference restored = program.getReferenceManager().addMemoryReference(start,
					saved.target, saved.type, saved.source, saved.operand);
				if (saved.primary) program.getReferenceManager().setPrimary(restored, true);
			}
		}
	}

	private record SavedReference(Address target, RefType type, SourceType source,
			int operand, boolean primary) {}

	private static Map<Address, List<Instruction>> recoverFfcCallers(Listing listing,
			TaskMonitor monitor) throws CancelledException {
		Map<Address, List<Instruction>> callersByTarget = new LinkedHashMap<>();
		InstructionIterator instructions = listing.getInstructions(true);
		while (instructions.hasNext()) {
			monitor.checkCancelled();
			Instruction instruction = instructions.next();
			Address target = ffcTarget(instruction);
			if (target != null) {
				callersByTarget.computeIfAbsent(target, ignored -> new ArrayList<>())
					.add(instruction);
			}
		}
		return callersByTarget;
	}

	private static FfcHelper recoverHelper(Program program, Address entry,
			List<Instruction> callers, Register switchContext,
			TaskMonitor monitor) throws CancelledException {
		Listing listing = program.getListing();
		Instruction first = listing.getInstructionAt(entry);
		if (first == null || callers.isEmpty() || hasFallthroughInto(first)) {
			return null;
		}
		if (!hasExclusiveFfcEntry(program, entry, callers)) {
			return null;
		}

		// Bounded architectural CFG closure. Every reachable exit must use the
		// incoming, unwritten XAR7; external entry into any interior node is forbidden.
		Map<Address, Instruction> body = new LinkedHashMap<>();
		List<Address> returns = new ArrayList<>();
		Deque<Instruction> pending = new ArrayDeque<>();
		pending.add(first);
		while (!pending.isEmpty()) {
			monitor.checkCancelled();
			Instruction current = pending.poll();
			if (hasInstructionOverride(current)) {
				return null;
			}
			if (body.containsKey(current.getMinAddress())) {
				continue;
			}
			if (body.size() >= MAX_HELPER_INSTRUCTIONS) {
				return null;
			}
			body.put(current.getMinAddress(), current);

			if (isXar7Branch(current)) {
				// The switch canonicalizer owns this opcode when it has claimed it,
				// and its context bit outranks this analyzer.
				if (BigInteger.ONE.equals(program.getProgramContext().getValue(switchContext,
					current.getMinAddress(), false))) {
					return null;
				}
				returns.add(current.getMinAddress());
				continue;   // an exit: nothing flows past it
			}
			if (writesRegister(current, "XAR7")) {
				return null;
			}
			// A call may clobber XAR7 (it is killedbycall), and a computed transfer has
			// no enumerable successor, so neither can be carried across. A terminal that
			// is not one of our exits ends a path we cannot account for. All three
			// simply fail the proof, exactly as the straight-line walk failed them.
			FlowType flow = current.getFlowType();
			if (flow.isCall() || flow.isTerminal() || flow.isComputed()) {
				return null;
			}

			for (Address target : current.getFlows()) {
				Instruction next = listing.getInstructionAt(target);
				if (next == null) {
					return null;
				}
				pending.add(next);
			}
			Address fallThrough = current.getFallThrough();
			if (fallThrough != null) {
				Instruction next = listing.getInstructionAt(fallThrough);
				if (next == null) {
					return null;
				}
				pending.add(next);
			}
			else if (current.getFlows().length == 0) {
				return null;   // no successor at all, and not an exit
			}
		}

		if (returns.isEmpty() || !hasExclusiveBodyIngress(program, entry, body.keySet())) {
			return null;
		}
		return new FfcHelper(entry, returns, callers.size(), body.size());
	}

	private static boolean hasExclusiveFfcEntry(Program program, Address entry,
			List<Instruction> callers) {
		Set<Address> expectedCallers = new HashSet<>();
		for (Instruction caller : callers) {
			if (!entry.equals(ffcTarget(caller))) {
				return false;
			}
			expectedCallers.add(caller.getMinAddress());
		}

		Set<Address> observedCallers = new HashSet<>();
		ReferenceIterator references = program.getReferenceManager().getReferencesTo(entry);
		while (references.hasNext()) {
			Reference reference = references.next();
			if (!reference.getReferenceType().isFlow()) {
				continue;
			}
			Instruction source = program.getListing().getInstructionAt(reference.getFromAddress());
			if (source == null || !entry.equals(ffcTarget(source)) ||
				!expectedCallers.contains(source.getMinAddress())) {
				return false;
			}
			observedCallers.add(source.getMinAddress());
		}
		return !observedCallers.isEmpty() && observedCallers.equals(expectedCallers);
	}

	private static boolean hasExclusiveBodyIngress(Program program, Address entry,
			Set<Address> bodyAddresses) {
		Listing listing = program.getListing();
		for (Address address : bodyAddresses) {
			if (address.equals(entry)) {
				continue;
			}
			Instruction instruction = listing.getInstructionAt(address);
			Instruction previous = instruction == null ? null : instruction.getPrevious();
			if (previous != null && !bodyAddresses.contains(previous.getMinAddress()) &&
				address.equals(previous.getFallThrough())) {
				return false;
			}
			ReferenceIterator references = program.getReferenceManager()
				.getReferencesTo(address);
			while (references.hasNext()) {
				Reference reference = references.next();
				if (reference.getReferenceType().isFlow() &&
					!bodyAddresses.contains(reference.getFromAddress())) {
					return false;
				}
			}
		}
		return true;
	}

	private static Address ffcTarget(Instruction instruction) {
		if (!isMnemonic(instruction, "ffc") || hasInstructionOverride(instruction) ||
			!instruction.getFlowType().isCall() ||
			!isRegisterOperand(instruction, 0, "XAR7")) {
			return null;
		}
		Address[] flows = instruction.getFlows();
		return flows.length == 1 ? flows[0] : null;
	}

	private static boolean isXar7Branch(Instruction instruction) {
		return isMnemonic(instruction, "lb") && isRegisterOperand(instruction, 0, "XAR7");
	}

	private static boolean hasInstructionOverride(Instruction instruction) {
		return instruction.getFlowOverride() != FlowOverride.NONE ||
			instruction.isFallThroughOverridden() || instruction.isLengthOverridden();
	}

	private static boolean hasFallthroughInto(Instruction instruction) {
		Instruction previous = instruction.getPrevious();
		return previous != null && instruction.getMinAddress().equals(previous.getFallThrough());
	}

	private static boolean writesRegister(Instruction instruction, String registerName) {
		Register expected = instruction.getProgram().getLanguage().getRegister(registerName);
		if (expected != null) {
			for (Object object : instruction.getResultObjects()) {
				if (object instanceof Register result &&
					(expected.contains(result) || result.contains(expected))) {
					return true;
				}
			}
		}
		// Decoder result objects are not guaranteed for every instruction.  Since
		// C28x syntax puts register destinations first, treating an XAR7 operand 0
		// as a write is a conservative fallback (and intentionally rejects PUSH).
		return isRegisterOperand(instruction, 0, registerName);
	}

	private static boolean isMnemonic(Instruction instruction, String mnemonic) {
		return instruction != null && instruction.getMnemonicString().equalsIgnoreCase(mnemonic);
	}

	private static boolean isRegisterOperand(Instruction instruction, int operand,
			String registerName) {
		if (instruction == null || operand >= instruction.getNumOperands()) {
			return false;
		}
		Register register = instruction.getRegister(operand);
		if (register != null) {
			return register.getName().equalsIgnoreCase(registerName);
		}
		Object[] objects = instruction.getOpObjects(operand);
		for (Object object : objects) {
			if (object instanceof Register objectRegister &&
				objectRegister.getName().equalsIgnoreCase(registerName)) {
				return true;
			}
		}
		return instruction.getDefaultOperandRepresentation(operand)
			.equalsIgnoreCase("*" + registerName);
	}

	private static final class FfcHelper {
		private final Address entryAddress;
		private final List<Address> returnAddresses;
		private final int callerCount;
		private final int instructionCount;

		private FfcHelper(Address entryAddress, List<Address> returnAddresses, int callerCount,
				int instructionCount) {
			this.entryAddress = entryAddress;
			this.returnAddresses = returnAddresses;
			this.callerCount = callerCount;
			this.instructionCount = instructionCount;
		}
	}
}
