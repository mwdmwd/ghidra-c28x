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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
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
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.JumpTable;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * Canonicalizes validated TI compiler switch dispatches before the generic
 * decompiler switch analyzer runs.
 * <p>
 * The C28x ABI does not prescribe SXM at function boundaries. Consequently,
 * ordinary index instructions must retain their SXM/OVM-sensitive semantics.
 * Validated switch guards, however, prove the bounded selector arithmetic on
 * the path into a dispatch. This analyzer recovers a complete switch descriptor,
 * validates the table and targets, and selects equivalent canonical SLEIGH
 * constructors only at the proven index (and, for the saved 32-bit-selector
 * schedule, its range subtraction) and {@code LB *XAR7}. Stock Decompiler Switch
 * Analysis then recovers the references, function body, and original case values.
 */
public class TMS320C28SwitchAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "TMS320C28 TI Switch Canonicalizer";
	private static final String DESCRIPTION =
		"Recognizes guarded TI switch tables and canonicalizes their unsigned index";
	private static final String PROCESSOR_NAME = "TMS320C28";
	private static final String CONTEXT_NAME = "switch_canonical";
	private static final int MAX_ENTRIES = 1024;
	private static final int MAX_DISPATCH_INSTRUCTIONS = 20;
	private static final long CODE_ADDRESS_MASK = 0x003fffffL;
	private static final long TABLE_ENTRY_WORDS = 2;
	private static final String OVERRIDE_OWNER_MARKER =
		"tms320c28_switch_analyzer_owned";

	public TMS320C28SwitchAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
		// Run after initial instruction discovery and before CODE_ANALYSIS, where
		// the generic Decompiler Switch Analysis is scheduled.
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
		Register switchContext = context.getRegister(CONTEXT_NAME);
		if (switchContext == null) {
			log.appendMsg(NAME, "missing SLEIGH context register " + CONTEXT_NAME);
			return false;
		}

		Listing listing = program.getListing();
		Map<Address, SwitchDescriptor> descriptors = new LinkedHashMap<>();
		Set<Address> validSites = new HashSet<>();

		// Context is an analysis conclusion rather than an input assumption.  Scan
		// the complete current listing, including already-tagged branches, so a
		// later alternate ingress, table mutation, or permission change can revoke
		// a stale conclusion deterministically.
		InstructionIterator instructions = listing.getInstructions(true);
		while (instructions.hasNext()) {
			monitor.checkCancelled();
			Instruction instruction = instructions.next();
			if (!isComputedXar7Branch(instruction)) {
				continue;
			}
			SwitchDescriptor descriptor = recoverSwitchDescriptor(program, instruction, monitor);
			if (descriptor == null) {
				continue;
			}
			descriptors.put(descriptor.branchAddress, descriptor);
			validSites.add(descriptor.branchAddress);
			validSites.add(descriptor.indexExpression.instruction.getMinAddress());
			if (descriptor.guardCanonicalInstruction != null) {
				validSites.add(descriptor.guardCanonicalInstruction.getMinAddress());
			}
		}

		// Descriptor targets are known executable instruction starts.  Disassemble
		// them before function-body publication so ordinary flow following can
		// include every case body rather than only the first sequential target.
		AddressSet descriptorTargets = new AddressSet();
		for (SwitchDescriptor descriptor : descriptors.values()) {
			if (descriptor.variant.requiresPublication) {
				for (Address target : descriptor.validatedTargets) {
					descriptorTargets.add(target);
				}
			}
		}
		if (!descriptorTargets.isEmpty()) {
			DisassembleCommand command = new DisassembleCommand(descriptorTargets, null, true);
			command.enableCodeAnalysis(false);
			if (!command.applyTo(program, monitor)) {
				log.appendMsg(NAME, "could not disassemble all proved switch targets: " +
					command.getStatusMsg());
			}
		}

		// The saved-selector AR6 families need an explicit, ordinary switch
		// descriptor.  Computed references plus canonical P-Code are insufficient
		// for stock Switch Analysis on these schedules, even after all targets are
		// disassembled and the containing body is repaired.  Publish the same
		// generic descriptor that a user override would contain, but mark it as
		// analyzer-owned so it can be revalidated, refreshed, and revoked.
		revokeStaleOwnedOverrides(program, descriptors, monitor, log);
		for (SwitchDescriptor descriptor : descriptors.values()) {
			monitor.checkCancelled();
			if (descriptor.variant.requiresPublication) {
				publishDerivedDescriptor(program, descriptor, monitor, log);
			}
		}

		List<Instruction> additions = new ArrayList<>();
		List<Instruction> revocations = new ArrayList<>();
		instructions = listing.getInstructions(true);
		while (instructions.hasNext()) {
			monitor.checkCancelled();
			Instruction instruction = instructions.next();
			boolean tagged = tagged(context, switchContext, instruction);
			boolean valid = validSites.contains(instruction.getMinAddress());
			if (valid && !tagged) {
				additions.add(instruction);
			}
			else if (tagged && !valid) {
				revocations.add(instruction);
			}
		}

		AddressSet redisassemble = new AddressSet();
		// Revoke stale assumptions before publishing new ones.  The ordinary
		// constructors are therefore restored even if analysis is interrupted
		// while processing the additions.
		for (Instruction instruction : revocations) {
			Address address = instruction.getMinAddress();
			changeContext(listing, context, switchContext, instruction,
				BigInteger.ZERO, redisassemble, log);
			Msg.info(this, "revoked stale switch context at " + address);
		}
		for (Instruction instruction : additions) {
			changeContext(listing, context, switchContext, instruction,
				BigInteger.ONE, redisassemble, log);
		}

		AddressSet switchBranches = new AddressSet();
		for (SwitchDescriptor descriptor : descriptors.values()) {
			switchBranches.add(descriptor.branchAddress);
			long highestCase = descriptor.lowestCase + descriptor.count - 1;
			Msg.info(this,
				"recognized " + descriptor.variant.description + " switch at " +
					descriptor.branchAddress + " table=" + descriptor.tableBase + " cases=" +
					descriptor.lowestCase + "-" + highestCase + " default=" +
					descriptor.defaultPath);
		}

		AutoAnalysisManager manager = AutoAnalysisManager.getAnalysisManager(program);
		if (!redisassemble.isEmpty()) {
			manager.disassemble(redisassemble, AnalysisPriority.DISASSEMBLY);
		}
		if (!switchBranches.isEmpty()) {
			// Redisassembly only reports the changed canonical sites.  Explicitly
			// resubmit every still-proved LB so stock switch analysis also reruns
			// when only references/body/override state changed.
			manager.scheduleOneTimeAnalysis(new DecompilerSwitchAnalyzer(), switchBranches);
		}
		return true;
	}

	private static boolean tagged(ProgramContext context, Register switchContext,
			Instruction instruction) {
		return BigInteger.ONE.equals(context.getValue(switchContext,
			instruction.getMinAddress(), false));
	}

	private static void changeContext(Listing listing, ProgramContext context,
			Register switchContext, Instruction instruction, BigInteger value,
			AddressSet redisassemble, MessageLog log) {
		try {
			Address start = instruction.getMinAddress();
			Address end = instruction.getMaxAddress();
			listing.clearCodeUnits(start, end, false);
			context.setValue(switchContext, start, end, value);
			redisassemble.add(start);
		}
		catch (ContextChangeException exception) {
			log.appendException(exception);
		}
	}

	private static void revokeStaleOwnedOverrides(Program program,
			Map<Address, SwitchDescriptor> descriptors, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		SymbolTable symbols = program.getSymbolTable();
		List<Symbol> markers = new ArrayList<>();
		SymbolIterator iterator = symbols.getSymbols(OVERRIDE_OWNER_MARKER);
		while (iterator.hasNext()) {
			monitor.checkCancelled();
			markers.add(iterator.next());
		}
		for (Symbol marker : markers) {
			monitor.checkCancelled();
			if (marker.getSource() != SourceType.ANALYSIS) {
				continue;
			}
			SwitchDescriptor descriptor = descriptors.get(marker.getAddress());
			if (descriptor != null && descriptor.variant.requiresOverride) {
				continue;
			}
			Function function = program.getFunctionManager()
					.getFunctionContaining(marker.getAddress());
			Namespace expectedNamespace = function == null ? null :
				findSwitchOverrideNamespace(function, marker.getAddress());
			if (expectedNamespace == null ||
				!expectedNamespace.equals(marker.getParentNamespace())) {
				// Never clear a namespace merely because it contains a coincidentally
				// named symbol.  Ownership is the conjunction of source, address, and
				// the standard jump-override namespace for the containing function.
				continue;
			}
			try {
				if (HighFunction.clearNamespace(symbols, expectedNamespace)) {
					removeAnalysisComputedJumpReferences(program, marker.getAddress());
					if (function != null) {
						CreateFunctionCmd.fixupFunctionBody(program, function, monitor);
					}
					Msg.info(TMS320C28SwitchAnalyzer.class,
						"revoked stale analyzer-owned switch override at " + marker.getAddress());
				}
				else {
					log.appendMsg(NAME,
						"could not clear owned switch namespace at " + marker.getAddress());
				}
			}
			catch (InvalidInputException exception) {
				log.appendException(exception);
			}
		}
	}

	private static void publishDerivedDescriptor(Program program, SwitchDescriptor descriptor,
			TaskMonitor monitor, MessageLog log) throws CancelledException {
		if (!descriptor.variant.requiresPublication) {
			return;
		}

		Function function = program.getFunctionManager()
				.getFunctionContaining(descriptor.branchAddress);
		if (function == null && descriptor.provenFunctionEntry != null) {
			CreateFunctionCmd create = new CreateFunctionCmd(descriptor.provenFunctionEntry);
			if (create.applyTo(program, monitor)) {
				function = create.getFunction();
			}
		}
		if (function == null) {
			// Normal Subroutine References analysis may not have run yet.  Do not
			// publish unowned references: a later analyzer invocation can create the
			// complete, revocable descriptor once the branch belongs to a function.
			return;
		}
		if (!function.getBody().contains(descriptor.branchAddress)) {
			log.appendMsg(NAME,
				"proved saved-selector switch is not in a function body at " +
					descriptor.branchAddress);
			return;
		}

		Namespace existing = findSwitchOverrideNamespace(function, descriptor.branchAddress);
		boolean owned = existing != null && hasOwnerMarker(program, existing,
			descriptor.branchAddress);
		if (existing != null && !owned) {
			// A manual/user override takes precedence.  Its namespace is deliberately
			// not marked by this analyzer and must never be rewritten or revoked here.
			return;
		}

		try {
			if (owned && !HighFunction.clearNamespace(program.getSymbolTable(), existing)) {
				log.appendMsg(NAME,
					"could not refresh owned switch namespace at " + descriptor.branchAddress);
				return;
			}
			JumpTable override = new JumpTable(descriptor.branchAddress,
				new ArrayList<>(descriptor.validatedTargets), true, 0);
			override.writeOverride(function);
			Namespace namespace = findSwitchOverrideNamespace(function, descriptor.branchAddress);
			if (namespace == null) {
				log.appendMsg(NAME,
					"failed to find published switch namespace at " + descriptor.branchAddress);
				return;
			}
			try {
				HighFunction.createLabelSymbol(program.getSymbolTable(), descriptor.branchAddress,
					OVERRIDE_OWNER_MARKER, namespace, SourceType.ANALYSIS, false);
			}
			catch (InvalidInputException exception) {
				// An unmarked override would be indistinguishable from user state and
				// therefore could not be safely refreshed or revoked.
				HighFunction.clearNamespace(program.getSymbolTable(), namespace);
				throw exception;
			}

			// Publish edges only after the ownership marker exists.  Thus every
			// reference this analyzer creates has a durable revocation key even if a
			// later analysis pass is interrupted.
			removeAnalysisComputedJumpReferences(program, descriptor.branchAddress);
			for (Address target : descriptor.validatedTargets) {
				monitor.checkCancelled();
				addComputedJumpReferenceIfMissing(program, descriptor.branchAddress, target);
			}
			CreateFunctionCmd.fixupFunctionBody(program, function, monitor);
		}
		catch (InvalidInputException exception) {
			log.appendException(exception);
		}
	}

	private static Namespace findSwitchOverrideNamespace(Function function, Address branch) {
		Namespace override = HighFunction.findOverrideSpace(function);
		if (override == null) {
			return null;
		}
		return HighFunction.findNamespace(function.getProgram().getSymbolTable(), override,
			"jmp_" + branch);
	}

	private static boolean hasOwnerMarker(Program program, Namespace namespace, Address branch) {
		return program.getSymbolTable().getSymbol(OVERRIDE_OWNER_MARKER, branch, namespace) != null;
	}

	private static void removeAnalysisComputedJumpReferences(Program program, Address branch) {
		List<Reference> remove = new ArrayList<>();
		for (Reference reference : program.getReferenceManager().getReferencesFrom(branch)) {
			if (reference.getReferenceType() == RefType.COMPUTED_JUMP &&
				reference.getSource() == SourceType.ANALYSIS) {
				remove.add(reference);
			}
		}
		for (Reference reference : remove) {
			program.getReferenceManager().delete(reference);
		}
	}

	private static void addComputedJumpReferenceIfMissing(Program program, Address branch,
			Address target) {
		for (Reference reference : program.getReferenceManager().getReferencesFrom(branch)) {
			if (reference.getReferenceType() == RefType.COMPUTED_JUMP &&
				reference.getToAddress().equals(target)) {
				return;
			}
		}
		program.getReferenceManager().addMemoryReference(branch, target,
			RefType.COMPUTED_JUMP, SourceType.ANALYSIS, Reference.MNEMONIC);
	}

	private static SwitchDescriptor recoverSwitchDescriptor(Program program, Instruction branch,
			TaskMonitor monitor) throws CancelledException {
		DispatchCandidate dispatch = recoverDispatch(branch);
		if (dispatch == null) {
			return null;
		}

		Guard guard = recoverSoleUnsignedGuard(program, dispatch, monitor);
		if (guard == null || !hasConsistentIndexArithmetic(dispatch.indexExpression, guard.low)) {
			return null;
		}
		if (!hasExclusiveStraightLineDispatch(program, guard, dispatch)) {
			return null;
		}

		List<Address> targets = validateTable(program, dispatch.tableBase, guard.count, branch);
		if (targets == null) {
			return null;
		}
		Address provenFunctionEntry = guard.variant == DispatchVariant.NATIVE_AR6_SAVED_STACK
				? guard.startInstruction.getMinAddress()
				: null;
		return new SwitchDescriptor(branch.getMinAddress(), dispatch.tableBase, guard.count,
			guard.low, guard.defaultPath, guard.canonicalInstruction, dispatch.indexExpression,
			targets, guard.variant, provenFunctionEntry);
	}

	private static DispatchCandidate recoverDispatch(Instruction branch) {
		DispatchCandidate candidate = recoverProgramReadSavedLongDispatch(branch);
		if (candidate != null) {
			return candidate;
		}
		candidate = recoverProgramReadDispatch(branch);
		if (candidate != null) {
			return candidate;
		}
		candidate = recoverNativePlDispatch(branch);
		if (candidate != null) {
			return candidate;
		}
		candidate = recoverNativeSavedLongDispatch(branch);
		if (candidate != null) {
			return candidate;
		}
		candidate = recoverNativeAr6Dispatch(branch);
		if (candidate != null) {
			return candidate;
		}
		return recoverNativeDirectDispatch(branch);
	}

	/**
	 * Recover the default-memory sibling of the saved-selector native form.
	 * TI cl2000 22.6.1.LTS emits this exact finite schedule for a 32-bit
	 * selector from -O0 through -O4: the selector is kept in XAR7 across an
	 * inverted HI guard, then a two-word program-space target is assembled
	 * with PREAD AL/AH before LB *XAR7.
	 */
	private static DispatchCandidate recoverProgramReadSavedLongDispatch(Instruction branch) {
		Instruction finalCopy = contiguousPrevious(branch);
		Instruction highRead = contiguousPrevious(finalCopy);
		Instruction increment = contiguousPrevious(highRead);
		Instruction lowRead = contiguousPrevious(increment);
		Instruction add = contiguousPrevious(lowRead);
		Instruction adjustmentInstruction = contiguousPrevious(add);
		Instruction scaleInstruction = contiguousPrevious(adjustmentInstruction);
		Instruction tableInstruction = contiguousPrevious(scaleInstruction);
		Instruction selectorCopy = contiguousPrevious(tableInstruction);
		Scalar tableScalar = immediateTableBase(tableInstruction);
		Long subtraction = recoverAccImmediateSubtraction(adjustmentInstruction);
		if (!isRegisterMove(finalCopy, "movl", "XAR7", "ACC") ||
			!isRegisterMove(highRead, "pread", "AH", "XAR7") ||
			!isImmediateAdd(increment, "addb", "XAR7", 1) ||
			!isRegisterMove(lowRead, "pread", "AL", "XAR7") ||
			!isRegisterMove(add, "addl", "XAR7", "ACC") ||
			!isLslAccByOne(scaleInstruction) || tableScalar == null || subtraction == null ||
			!isRegisterMove(selectorCopy, "movl", "ACC", "XAR7")) {
			return null;
		}

		Address table = tableAddress(tableInstruction, tableScalar);
		IndexExpression expression =
			new IndexExpression(adjustmentInstruction, "XAR7", TABLE_ENTRY_WORDS,
				-subtraction.longValue());
		return new DispatchCandidate(selectorCopy, branch, table, expression,
			DispatchVariant.PROGRAM_READ_SAVED_LONG);
	}

	private static DispatchCandidate recoverProgramReadDispatch(Instruction branch) {
		Instruction finalCopy = contiguousPrevious(branch);
		Instruction highRead = contiguousPrevious(finalCopy);
		Instruction increment = contiguousPrevious(highRead);
		Instruction lowRead = contiguousPrevious(increment);
		Instruction addressCopy = contiguousPrevious(lowRead);
		if (!isRegisterMove(finalCopy, "movl", "XAR7", "ACC") ||
			!isRegisterMove(highRead, "pread", "AH", "XAR7") ||
			!isImmediateAdd(increment, "addb", "XAR7", 1) ||
			!isRegisterMove(lowRead, "pread", "AL", "XAR7") ||
			!isRegisterMove(addressCopy, "movl", "XAR7", "ACC")) {
			return null;
		}
		return recoverPlAddressComputation(addressCopy, branch, DispatchVariant.PROGRAM_READ);
	}

	private static DispatchCandidate recoverNativePlDispatch(Instruction branch) {
		Instruction load = contiguousPrevious(branch);
		Instruction addressCopy = contiguousPrevious(load);
		if (!isNativeLongwordLoad(load) ||
			!isRegisterMove(addressCopy, "movl", "XAR7", "ACC")) {
			return null;
		}
		return recoverPlAddressComputation(addressCopy, branch, DispatchVariant.NATIVE_PL);
	}

	/**
	 * Recover 32-bit-selector schedules used by TI firmware that keep the
	 * unadjusted selector in either XAR7 or P across a range guard:
	 *
	 * <pre>
	 * MOVL ACC,XAR7 | MOVL ACC,P
	 * MOVL XAR7,#table
	 * LSL  ACC,1
	 * SUB  ACC,#(2 * low)
	 * ADDL XAR7,ACC
	 * MOVL XAR7,*+XAR7[0]
	 * LB   *XAR7
	 * </pre>
	 *
	 * LSL already has unambiguous 32-bit semantics. The analyzer canonicalizes
	 * the following SUB, whose ordinary P-Code must retain SXM/OVM behavior, and
	 * the validated LB.
	 */
	private static DispatchCandidate recoverNativeSavedLongDispatch(Instruction branch) {
		Instruction load = contiguousPrevious(branch);
		Instruction add = contiguousPrevious(load);
		Instruction adjustmentInstruction = contiguousPrevious(add);
		Instruction scaleInstruction = contiguousPrevious(adjustmentInstruction);
		Instruction tableInstruction = contiguousPrevious(scaleInstruction);
		Instruction selectorCopy = contiguousPrevious(tableInstruction);
		Scalar tableScalar = immediateTableBase(tableInstruction);
		Long subtraction = recoverAccImmediateSubtraction(adjustmentInstruction);
		Long subb = recoverAccImmediateSubb(adjustmentInstruction);
		String savedRegister;
		DispatchVariant variant;
		if (isRegisterMove(selectorCopy, "movl", "ACC", "XAR7")) {
			savedRegister = "XAR7";
			variant = subb != null
					? DispatchVariant.NATIVE_SAVED_LONG_SUBB
					: DispatchVariant.NATIVE_SAVED_LONG;
		}
		else if (isRegisterMove(selectorCopy, "movl", "ACC", "P")) {
			if (subb != null) {
				return null;
			}
			savedRegister = "P";
			variant = DispatchVariant.NATIVE_SAVED_P;
		}
		else {
			return null;
		}
		if (!isNativeLongwordLoad(load) ||
			!isRegisterMove(add, "addl", "XAR7", "ACC") ||
			!isLslAccByOne(scaleInstruction) || tableScalar == null ||
			(subtraction == null && subb == null)) {
			return null;
		}

		Address table = tableAddress(tableInstruction, tableScalar);
		long adjustment = subtraction != null ? subtraction.longValue() : subb.longValue();
		IndexExpression expression =
			new IndexExpression(adjustmentInstruction, savedRegister, TABLE_ENTRY_WORDS,
				-adjustment);
		return new DispatchCandidate(selectorCopy, branch, table, expression, variant);
	}

	private static DispatchCandidate recoverPlAddressComputation(Instruction addressCopy,
			Instruction branch, DispatchVariant variant) {
		Instruction add = contiguousPrevious(addressCopy);
		Instruction baseCopy = contiguousPrevious(add);
		Instruction adjustmentInstruction = contiguousPrevious(baseCopy);
		Instruction scaledCopy = contiguousPrevious(adjustmentInstruction);
		if (!isRegisterMove(add, "addu", "ACC", "PL") ||
			!isRegisterMove(baseCopy, "movl", "ACC", "XAR7") ||
			!isRegisterMove(scaledCopy, "mov", "PL", "AL")) {
			return null;
		}

		Long adjustment = recoverRegisterImmediateAdjustment(adjustmentInstruction, "PL");
		if (adjustment == null) {
			return null;
		}

		IndexAndTable pair = recoverAdjacentIndexAndTable(contiguousPrevious(scaledCopy));
		if (pair == null) {
			return null;
		}
		Address table = tableAddress(pair.tableInstruction, pair.tableScalar);
		IndexExpression expression =
			new IndexExpression(pair.indexInstruction, pair.indexSource, TABLE_ENTRY_WORDS,
				adjustment.longValue());
		return new DispatchCandidate(pair.entryInstruction, branch, table, expression, variant);
	}

	/**
	 * Recover the finite zero-based AR6 schedule observed at firmware
	 * 0x90615-0x90621:
	 *
	 * <pre>
	 * MOVZ AR6,mem16
	 * MOV  AL,AR6
	 * CMPB AL,#high
	 * SB   default,HI
	 * MOVL XAR7,#table
	 * SETC SXM
	 * MOVL ACC,XAR7
	 * ADD  ACC,AR6 << #1
	 * MOVL XAR7,ACC
	 * MOVL XAR7,*+XAR7[0]
	 * LB   *XAR7
	 * </pre>
	 *
	 * Every instruction and operand is matched exactly.  MOVZ and the unsigned
	 * guard prove a nonnegative bounded selector, while SETC SXM makes the ADD's
	 * extension mode explicit.  The analyzer canonicalizes only that ADD and the
	 * validated computed branch.
	 */
	private static DispatchCandidate recoverNativeAr6Dispatch(Instruction branch) {
		Instruction load = contiguousPrevious(branch);
		Instruction finalCopy = contiguousPrevious(load);
		Instruction indexAdd = contiguousPrevious(finalCopy);
		Instruction baseCopy = contiguousPrevious(indexAdd);
		Instruction setSxm = contiguousPrevious(baseCopy);
		Instruction tableInstruction = contiguousPrevious(setSxm);
		Scalar tableScalar = immediateTableBase(tableInstruction);
		SxmMode sxmMode = recoverSxmMode(setSxm);
		if (!isNativeLongwordLoad(load) ||
			!isRegisterMove(finalCopy, "movl", "XAR7", "ACC") ||
			!isAr6ScaledAdd(indexAdd) ||
			!isRegisterMove(baseCopy, "movl", "ACC", "XAR7") ||
			sxmMode == null || tableScalar == null) {
			return null;
		}

		Address table = tableAddress(tableInstruction, tableScalar);
		IndexExpression expression =
			new IndexExpression(indexAdd, "AR6", TABLE_ENTRY_WORDS, 0);
		return new DispatchCandidate(tableInstruction, branch, table, expression,
			sxmMode == SxmMode.SET
					? DispatchVariant.NATIVE_AR6_ZERO
					: DispatchVariant.NATIVE_AR6_SAVED_STACK);
	}

	private static DispatchCandidate recoverNativeDirectDispatch(Instruction branch) {
		Instruction load = contiguousPrevious(branch);
		Instruction add = contiguousPrevious(load);
		if (!isNativeLongwordLoad(load) ||
			!isRegisterMove(add, "addl", "XAR7", "ACC")) {
			return null;
		}

		DirectIndexAndTable direct = recoverDirectIndexAndTable(contiguousPrevious(add), 3);
		if (direct == null) {
			direct = recoverDirectIndexAndTable(contiguousPrevious(add), 2);
		}
		if (direct == null) {
			return null;
		}

		Address table = tableAddress(direct.tableInstruction, direct.tableScalar);
		IndexExpression expression =
			new IndexExpression(direct.indexInstruction, direct.indexSource, TABLE_ENTRY_WORDS,
				direct.adjustment);
		return new DispatchCandidate(direct.entryInstruction, branch, table, expression,
			DispatchVariant.NATIVE_DIRECT);
	}

	private static DirectIndexAndTable recoverDirectIndexAndTable(Instruction last, int length) {
		if (last == null || (length != 2 && length != 3)) {
			return null;
		}
		List<Instruction> instructions = new ArrayList<>(length);
		Instruction current = last;
		for (int i = 0; i < length; i++) {
			if (current == null) {
				return null;
			}
			instructions.add(0, current);
			current = contiguousPrevious(current);
		}

		Instruction tableInstruction = null;
		Scalar tableScalar = null;
		Instruction indexInstruction = null;
		String indexSource = null;
		Instruction adjustmentInstruction = null;
		int indexPosition = -1;
		int adjustmentPosition = -1;
		for (int i = 0; i < instructions.size(); i++) {
			Instruction instruction = instructions.get(i);
			Scalar scalar = immediateTableBase(instruction);
			String source = indexSource(instruction);
			if (scalar != null) {
				if (tableInstruction != null) {
					return null;
				}
				tableInstruction = instruction;
				tableScalar = scalar;
			}
			else if (source != null) {
				if (indexInstruction != null) {
					return null;
				}
				indexInstruction = instruction;
				indexSource = source;
				indexPosition = i;
			}
			else if (isAccImmediateSubtraction(instruction)) {
				if (adjustmentInstruction != null) {
					return null;
				}
				adjustmentInstruction = instruction;
				adjustmentPosition = i;
			}
			else {
				return null;
			}
		}

		if (tableInstruction == null || indexInstruction == null ||
			(length == 3) != (adjustmentInstruction != null) ||
			(adjustmentInstruction != null && adjustmentPosition <= indexPosition)) {
			return null;
		}
		long adjustment = adjustmentInstruction == null
				? 0
				: -recoverAccImmediateSubtraction(adjustmentInstruction).longValue();
		return new DirectIndexAndTable(instructions.get(0), tableInstruction, tableScalar,
			indexInstruction, indexSource, adjustment);
	}

	private static IndexAndTable recoverAdjacentIndexAndTable(Instruction last) {
		Instruction first = contiguousPrevious(last);
		if (first == null || last == null) {
			return null;
		}

		Scalar firstTable = immediateTableBase(first);
		Scalar lastTable = immediateTableBase(last);
		String firstIndex = indexSource(first);
		String lastIndex = indexSource(last);
		if (firstIndex != null && lastTable != null) {
			return new IndexAndTable(first, first, firstIndex, last, lastTable);
		}
		if (firstTable != null && lastIndex != null) {
			return new IndexAndTable(first, last, lastIndex, first, firstTable);
		}
		return null;
	}

	private static Guard recoverSoleUnsignedGuard(Program program, DispatchCandidate dispatch,
			TaskMonitor monitor) throws CancelledException {
		ReferenceIterator references =
			program.getReferenceManager().getReferencesTo(dispatch.entryInstruction.getMinAddress());
		Guard match = null;
		while (references.hasNext()) {
			monitor.checkCancelled();
			Reference reference = references.next();
			if (!reference.getReferenceType().isJump() ||
				!reference.getReferenceType().isConditional()) {
				continue;
			}
			Instruction guardInstruction =
				program.getListing().getInstructionAt(reference.getFromAddress());
			Guard guard = recoverUnsignedRange(guardInstruction, dispatch);
			if (guard == null) {
				continue;
			}
			if (match != null) {
				return null;
			}
			match = guard;
		}

		// Some TI schedules invert the usual layout: HI branches to the default
		// while the bounded LOS path falls through directly into the dispatch.
		Guard fallthroughGuard =
			recoverUnsignedRange(contiguousPrevious(dispatch.entryInstruction), dispatch);
		if (fallthroughGuard != null) {
			if (match != null) {
				return null;
			}
			match = fallthroughGuard;
		}
		return match;
	}

	private static Guard recoverUnsignedRange(Instruction guard, DispatchCandidate dispatch) {
		Address defaultPath = unsignedGuardDefaultPath(guard, dispatch);
		if (defaultPath == null) {
			return null;
		}
		if (dispatch.variant == DispatchVariant.NATIVE_AR6_SAVED_STACK) {
			return recoverAr6SavedStackRange(guard, dispatch, defaultPath);
		}
		if (dispatch.variant == DispatchVariant.NATIVE_AR6_ZERO) {
			Guard saved = recoverAr6SavedGlobalRange(guard, dispatch, defaultPath);
			return saved != null ? saved : recoverAr6ZeroBasedRange(guard, defaultPath);
		}
		if (dispatch.variant == DispatchVariant.NATIVE_SAVED_LONG_SUBB) {
			return recoverUnsignedSubbLongRange(guard, dispatch, defaultPath);
		}

		Instruction compare = contiguousPrevious(guard);
		Instruction subtract = contiguousPrevious(compare);
		if (subtract == null) {
			return null;
		}
		if (isMnemonic(compare, "cmpl")) {
			return recoverUnsignedLongRange(guard, dispatch, defaultPath, compare, subtract);
		}
		if (!isMnemonic(compare, "cmpb") || !isRegisterOperand(compare, 0, "AL")) {
			return null;
		}

		Long lowValue = recoverGuardLow(subtract);
		Scalar highScalar = scalarOperand(compare, 1);
		if (lowValue == null || highScalar == null) {
			return null;
		}
		long low = lowValue.longValue();
		long count = highScalar.getUnsignedValue() + 1;
		long high = low + count - 1;
		if (low < 0 || count < 2 || count > MAX_ENTRIES || high > 0x7fff) {
			return null;
		}

		Instruction possibleCopy = contiguousPrevious(subtract);
		Instruction guardStart = subtract;
		boolean copiedSelector = isSelectorCopy(possibleCopy);
		if (copiedSelector) {
			guardStart = possibleCopy;
		}
		if (dispatch.indexExpression.sourceRegister.equals("AH") && !copiedSelector) {
			return null;
		}
		if (!hasExclusiveStraightLineGuard(guardStart, subtract, compare, guard)) {
			return null;
		}
		return new Guard(guard, guardStart, null, low, (int) count, defaultPath,
			dispatch.variant);
	}

	private static Guard recoverAr6ZeroBasedRange(Instruction guard, Address defaultPath) {
		Instruction compare = contiguousPrevious(guard);
		Instruction copy = contiguousPrevious(compare);
		Instruction producer = contiguousPrevious(copy);
		if (!isMnemonic(compare, "cmpb") || !isRegisterOperand(compare, 0, "AL") ||
			!isRegisterMove(copy, "mov", "AL", "AR6") ||
			!isMovzMemoryToAr6(producer)) {
			return null;
		}
		Scalar highScalar = scalarOperand(compare, 1);
		if (highScalar == null) {
			return null;
		}
		long count = highScalar.getUnsignedValue() + 1;
		if (count < 2 || count > MAX_ENTRIES || highScalar.getUnsignedValue() > 0x7fff ||
			!hasExclusiveStraightLineGuard(producer, copy, compare, guard)) {
			return null;
		}
		return new Guard(guard, producer, null, 0, (int) count, defaultPath,
			DispatchVariant.NATIVE_AR6_ZERO);
	}

	private static Guard recoverAr6SavedGlobalRange(Instruction guard,
			DispatchCandidate dispatch, Address defaultPath) {
		return recoverAr6SavedRange(guard, dispatch, defaultPath, false);
	}

	private static Guard recoverAr6SavedStackRange(Instruction guard,
			DispatchCandidate dispatch, Address defaultPath) {
		return recoverAr6SavedRange(guard, dispatch, defaultPath, true);
	}

	/**
	 * Recover only the two proved save/reload schedules.  The unconditional B is
	 * deliberately part of the proof: it must be the sole direct ingress to the
	 * compare, while the exact MOVZ reload is the only instruction between CMPB
	 * and SB and therefore preserves the guard flags.
	 */
	private static Guard recoverAr6SavedRange(Instruction guard,
			DispatchCandidate dispatch, Address defaultPath, boolean stack) {
		Instruction reload = contiguousPrevious(guard);
		Instruction compare = contiguousPrevious(reload);
		Instruction ingress = soleDirectUnconditionalIngress(compare);
		Instruction save = contiguousPrevious(ingress);
		if (!isUnsignedConditionalBranch(guard, "HI") ||
			!isMnemonic(compare, "cmpb") || !isRegisterOperand(compare, 0, "AL") ||
			!isMovzMemoryToAr6(reload) || ingress == null ||
			!isMemoryStoreFromAl(save) || !sameOperand(save, 0, reload, 1)) {
			return null;
		}

		Scalar highScalar = scalarOperand(compare, 1);
		if (highScalar == null) {
			return null;
		}
		long count = highScalar.getUnsignedValue() + 1;
		if (count < 2 || count > MAX_ENTRIES || highScalar.getUnsignedValue() > 0x7fff) {
			return null;
		}

		Instruction start;
		DispatchVariant finalVariant;
		if (stack) {
			Instruction stackEntry = recoverStackSelectorEntry(save.getProgram(), save);
			if (dispatch.variant != DispatchVariant.NATIVE_AR6_SAVED_STACK ||
				!isExactStackSelectorOperand(save, 0) ||
				stackEntry == null) {
				return null;
			}
			start = stackEntry;
			finalVariant = DispatchVariant.NATIVE_AR6_SAVED_STACK;
		}
		else {
			Instruction producer = recoverGlobalSelectorProducer(save);
			if (dispatch.variant != DispatchVariant.NATIVE_AR6_ZERO ||
				producer == null) {
				return null;
			}
			start = producer;
			finalVariant = DispatchVariant.NATIVE_AR6_SAVED_GLOBAL;
		}

		if (!fallsThroughTo(save, ingress.getMinAddress()) ||
			!fallsThroughTo(compare, reload.getMinAddress()) ||
			!fallsThroughTo(reload, guard.getMinAddress()) ||
			hasExplicitFlowReferenceTo(ingress) ||
			hasExplicitFlowReferenceTo(reload) ||
			hasExplicitFlowReferenceTo(guard)) {
			return null;
		}
		return new Guard(guard, start, null, 0, (int) count, defaultPath,
			finalVariant);
	}

	/**
	 * Prove the global selector value saved immediately before the sole
	 * dispatcher ingress.  The observed firmware changes DP between the load of
	 * AL and the store to the dedicated save slot, so those two MOV operations
	 * are not instruction-adjacent.  Admit only that one exact immediate DP load:
	 * it cannot modify AL, and every instruction after the producer must have a
	 * unique straight-line predecessor.  This is deliberately not a generic
	 * memory-alias or stack-reload walk.
	 */
	private static Instruction recoverGlobalSelectorProducer(Instruction save) {
		Instruction next = save;
		Instruction current = contiguousPrevious(next);
		boolean skippedDpLoad = false;
		while (current != null) {
			if (!fallsThroughTo(current, next.getMinAddress()) ||
				hasExplicitFlowReferenceTo(next)) {
				return null;
			}
			if (isMovAlFromMemory(current)) {
				return current;
			}
			if (skippedDpLoad || !isImmediateDpLoad(current)) {
				return null;
			}
			skippedDpLoad = true;
			next = current;
			current = contiguousPrevious(current);
		}
		return null;
	}

	private static Guard recoverUnsignedSubbLongRange(Instruction guard,
			DispatchCandidate dispatch, Address defaultPath) {
		Instruction compare = contiguousPrevious(guard);
		Instruction subtract = contiguousPrevious(compare);
		Instruction selectorCopy = contiguousPrevious(subtract);
		Instruction bound = contiguousPrevious(selectorCopy);
		Instruction producer = contiguousPrevious(bound);
		Long lowValue = recoverAccImmediateSubb(subtract);
		Scalar boundScalar = scalarOperand(bound, 1);
		if (lowValue == null || boundScalar == null ||
			!isMnemonic(compare, "cmpl") ||
			!isRegisterOperand(compare, 0, "ACC") ||
			!isRegisterOperand(compare, 1, "XAR6") ||
			!isRegisterMove(selectorCopy, "movl", "ACC", "XAR7") ||
			!isMnemonic(bound, "movb") || !isRegisterOperand(bound, 0, "XAR6") ||
			!isMovlMemoryToRegister(producer, "XAR7") ||
			!hasExclusiveStraightLineGuard(producer, subtract, compare, guard)) {
			return null;
		}

		long low = lowValue.longValue();
		long highOffset = boundScalar.getUnsignedValue();
		long count = highOffset + 1;
		long tailSubtraction = -dispatch.indexExpression.adjustmentWords;
		if (count < 2 || count > MAX_ENTRIES ||
			!provesSafeSubbDispatch(low, highOffset, tailSubtraction)) {
			return null;
		}
		return new Guard(guard, producer, subtract, low, (int) count, defaultPath,
			DispatchVariant.NATIVE_SAVED_LONG_SUBB);
	}

	private static boolean provesSafeSubbDispatch(long low, long highOffset,
			long tailSubtraction) {
		if (low < 0 || highOffset < 1 || tailSubtraction != TABLE_ENTRY_WORDS * low) {
			return false;
		}
		long highestSelector;
		long highestScaled;
		try {
			highestSelector = Math.addExact(low, highOffset);
			highestScaled = Math.multiplyExact(highestSelector, TABLE_ENTRY_WORDS);
		}
		catch (ArithmeticException exception) {
			return false;
		}
		// A selector below low wraps the first unsigned SUBB to a value above
		// the finite bound and is rejected by HI.  On the dispatch path the first
		// subtraction is therefore [0,highOffset], and the scaled selector is at
		// least 2*low before the second subtraction.  Keeping the complete range
		// below signed 32-bit maximum proves no borrow, signed overflow, OVC
		// update, or OVM saturation at either matched SUBB.
		return highestSelector <= Integer.MAX_VALUE &&
			highestScaled <= Integer.MAX_VALUE && tailSubtraction <= Integer.MAX_VALUE;
	}

	private static Guard recoverUnsignedLongRange(Instruction guard, DispatchCandidate dispatch,
			Address defaultPath, Instruction compare, Instruction subtract) {
		String savedRegister = dispatch.indexExpression.sourceRegister;
		String boundRegister;
		boolean selectorRelated;
		if (savedRegister.equals("XAR7")) {
			boundRegister = "XAR6";
			Instruction selectorRelation = contiguousPrevious(subtract);
			selectorRelated = isRegisterMove(selectorRelation, "movl", "XAR7", "ACC") ||
				isRegisterMove(selectorRelation, "movl", "ACC", "XAR7");
		}
		else if (savedRegister.equals("P")) {
			boundRegister = "XAR7";
			selectorRelated =
				isRegisterMove(contiguousPrevious(subtract), "movl", "P", "ACC");
		}
		else {
			return null;
		}

		Long lowValue = recoverAccImmediateSubtraction(subtract);
		if (lowValue == null || !selectorRelated ||
			!isRegisterOperand(compare, 0, "ACC") ||
			!isRegisterOperand(compare, 1, boundRegister)) {
			return null;
		}

		RegisterBound bound = recoverImmediateRegisterBound(subtract, boundRegister);
		if (bound == null) {
			return null;
		}
		long low = lowValue.longValue();
		long count = bound.highInclusive + 1;
		long high = low + count - 1;
		if (count < 2 || count > MAX_ENTRIES || high > Integer.MAX_VALUE / 2 ||
			!hasExclusiveStraightLineGuard(bound.instruction, subtract, compare, guard)) {
			return null;
		}
		return new Guard(guard, bound.instruction, subtract, low, (int) count, defaultPath,
			dispatch.variant);
	}

	private static RegisterBound recoverImmediateRegisterBound(Instruction subtract,
			String registerName) {
		Instruction next = subtract;
		Instruction current = contiguousPrevious(next);
		for (int count = 0; count < 10 && current != null; count++) {
			if (!fallsThroughTo(current, next.getMinAddress())) {
				return null;
			}
			if (writesRegister(current, registerName)) {
				Scalar scalar = scalarOperand(current, 1);
				if (!isMnemonic(current, "movb") ||
					!isRegisterOperand(current, 0, registerName) || scalar == null) {
					return null;
				}
				return new RegisterBound(current, scalar.getUnsignedValue());
			}
			next = current;
			current = contiguousPrevious(current);
		}
		return null;
	}

	private static boolean hasConsistentIndexArithmetic(IndexExpression expression, long low) {
		if (expression.scaleWords != TABLE_ENTRY_WORDS) {
			return false;
		}
		long expectedAdjustment;
		if (expression.sourceRegister.equals("AH") ||
			expression.sourceRegister.equals("XAR7") ||
			expression.sourceRegister.equals("P")) {
			expectedAdjustment = -TABLE_ENTRY_WORDS * low;
		}
		else if (expression.sourceRegister.equals("AL") ||
			expression.sourceRegister.equals("AR6")) {
			expectedAdjustment = 0;
		}
		else {
			return false;
		}
		return expression.adjustmentWords == expectedAdjustment;
	}

	private static boolean hasExclusiveStraightLineGuard(Instruction start, Instruction subtract,
			Instruction compare, Instruction guard) {
		List<Instruction> sequence = new ArrayList<>();
		Instruction current = start;
		while (current != null && sequence.size() < 12) {
			sequence.add(current);
			if (current.equals(guard)) {
				break;
			}
			current = contiguousNext(current);
		}
		if (sequence.isEmpty() || !sequence.get(sequence.size() - 1).equals(guard) ||
			!sequence.contains(subtract) || !sequence.contains(compare)) {
			return false;
		}
		for (int i = 0; i < sequence.size() - 1; i++) {
			if (!fallsThroughTo(sequence.get(i), sequence.get(i + 1).getMinAddress())) {
				return false;
			}
		}
		for (int i = 1; i < sequence.size(); i++) {
			if (hasExplicitFlowReferenceTo(sequence.get(i))) {
				return false;
			}
		}
		return true;
	}

	private static boolean hasExclusiveStraightLineDispatch(Program program, Guard guard,
			DispatchCandidate dispatch) {
		Instruction entry = dispatch.entryInstruction;
		Instruction previous = entry.getPrevious();
		if (previous != null && fallsThroughTo(previous, entry.getMinAddress()) &&
			!previous.equals(guard.instruction)) {
			return false;
		}

		Instruction current = entry;
		Instruction prior = null;
		for (int count = 0; count < MAX_DISPATCH_INSTRUCTIONS && current != null; count++) {
			ReferenceIterator references =
				program.getReferenceManager().getReferencesTo(current.getMinAddress());
			while (references.hasNext()) {
				Reference reference = references.next();
				if (!reference.getReferenceType().isFlow()) {
					continue;
				}
				if (!current.equals(entry) ||
					!reference.getFromAddress().equals(guard.instruction.getMinAddress())) {
					return false;
				}
			}

			if (current.equals(dispatch.branchInstruction)) {
				return prior != null;
			}
			Instruction next = contiguousNext(current);
			if (next == null || !fallsThroughTo(current, next.getMinAddress())) {
				return false;
			}
			prior = current;
			current = next;
		}
		return false;
	}

	private static List<Address> validateTable(Program program, Address table, int count,
			Instruction branch) {
		Memory memory = program.getMemory();
		MemoryBlock tableBlock = memory.getBlock(table);
		MemoryBlock branchBlock = memory.getBlock(branch.getMinAddress());
		if (tableBlock == null || !tableBlock.isInitialized() || !tableBlock.isLoaded() ||
			!tableBlock.isRead() || tableBlock.isWrite() || branchBlock == null ||
			!branchBlock.isExecute()) {
			return null;
		}

		try {
			int wordSize = table.getAddressSpace().getAddressableUnitSize();
			Address tableEnd = table.add((long) count * TABLE_ENTRY_WORDS * wordSize - 1);
			if (!tableBlock.contains(tableEnd)) {
				return null;
			}

			Function branchFunction =
				program.getFunctionManager().getFunctionContaining(branch.getMinAddress());
			Set<Long> distinctTargets = new HashSet<>();
			List<Address> targets = new ArrayList<>(count);
			for (int index = 0; index < count; index++) {
				Address entry = table.add((long) index * TABLE_ENTRY_WORDS * wordSize);
				long low = memory.getShort(entry, false) & 0xffffL;
				long high = memory.getShort(entry.add(wordSize), false) & 0xffffL;
				long rawTarget = (high << 16) | low;
				if ((rawTarget & ~CODE_ADDRESS_MASK) != 0) {
					return null;
				}
				long targetOffset = rawTarget & CODE_ADDRESS_MASK;
				Address target = wordAddress(table, targetOffset);
				MemoryBlock targetBlock = memory.getBlock(target);
				if (targetBlock == null || targetBlock != branchBlock ||
					!targetBlock.isInitialized() || !targetBlock.isLoaded() ||
					!targetBlock.isExecute()) {
					return null;
				}
				Function targetFunction =
					program.getFunctionManager().getFunctionContaining(target);
				if (hasCallReferenceTo(program, target) ||
					(targetFunction != null && targetFunction != branchFunction)) {
					// Function creation can run after this analyzer. Reject explicit
					// call destinations and targets already owned by another function,
					// whether they are entries or interior addresses.
					return null;
				}
				distinctTargets.add(targetOffset);
				targets.add(target);
			}
			return distinctTargets.size() >= Math.min(3, count) ? List.copyOf(targets) : null;
		}
		catch (MemoryAccessException | RuntimeException exception) {
			return null;
		}
	}

	private static boolean hasCallReferenceTo(Program program, Address target) {
		ReferenceIterator references = program.getReferenceManager().getReferencesTo(target);
		while (references.hasNext()) {
			if (references.next().getReferenceType().isCall()) {
				return true;
			}
		}
		return false;
	}

	private static boolean isComputedXar7Branch(Instruction instruction) {
		return isMnemonic(instruction, "lb") && isRegisterOperand(instruction, 0, "XAR7") &&
			instruction.getFlowType().isJump() && instruction.getFlowType().isComputed();
	}

	private static boolean isNativeLongwordLoad(Instruction instruction) {
		if (!isMnemonic(instruction, "movl") || !isRegisterOperand(instruction, 0, "XAR7") ||
			instruction.getNumOperands() != 2 ||
			!OperandType.isDynamic(instruction.getOperandType(1))) {
			return false;
		}
		Object[] objects = instruction.getOpObjects(1);
		if (objects.length != 2 || !(objects[0] instanceof Register register) ||
			!(objects[1] instanceof Scalar offset)) {
			return false;
		}
		return register.getName().equalsIgnoreCase("XAR7") && offset.getSignedValue() == 0;
	}

	private static Scalar immediateTableBase(Instruction instruction) {
		if (!isMnemonic(instruction, "movl") || !isRegisterOperand(instruction, 0, "XAR7")) {
			return null;
		}
		Scalar scalar = scalarOperand(instruction, 1);
		return scalar != null && (scalar.getUnsignedValue() & ~CODE_ADDRESS_MASK) == 0
				? scalar
				: null;
	}

	private static Address tableAddress(Instruction tableInstruction, Scalar scalar) {
		return wordAddress(tableInstruction.getAddress(), scalar.getUnsignedValue());
	}

	private static String indexSource(Instruction instruction) {
		Scalar shift = scalarOperand(instruction, 2);
		if (!isMnemonic(instruction, "mov") || !isRegisterOperand(instruction, 0, "ACC") ||
			shift == null || shift.getUnsignedValue() != 1) {
			return null;
		}
		if (isRegisterOperand(instruction, 1, "AH")) {
			return "AH";
		}
		return isRegisterOperand(instruction, 1, "AL") ? "AL" : null;
	}

	private static boolean isAccImmediateSubtraction(Instruction instruction) {
		return recoverAccImmediateSubtraction(instruction) != null;
	}

	private static Long recoverAccImmediateSubtraction(Instruction instruction) {
		if (!isMnemonic(instruction, "sub") || !isRegisterOperand(instruction, 0, "ACC")) {
			return null;
		}
		Scalar value = scalarOperand(instruction, 1);
		Scalar shift = scalarOperand(instruction, 2);
		if (value == null || value.getUnsignedValue() > 0x7fff) {
			// Keeping bit 15 clear makes the operand independent of SXM.
			return null;
		}
		long shiftValue = shift == null ? 0 : shift.getUnsignedValue();
		if (shiftValue > 15) {
			return null;
		}
		long shifted = value.getUnsignedValue() << shiftValue;
		return shifted <= Integer.MAX_VALUE ? shifted : null;
	}

	private static Long recoverAccImmediateSubb(Instruction instruction) {
		if (!isMnemonic(instruction, "subb") ||
			!isRegisterOperand(instruction, 0, "ACC") || instruction.getNumOperands() != 2) {
			return null;
		}
		Scalar value = scalarOperand(instruction, 1);
		return value != null && value.getUnsignedValue() <= 0xff
				? value.getUnsignedValue()
				: null;
	}

	private static Long recoverRegisterImmediateAdjustment(Instruction instruction,
			String destination) {
		if (instruction == null || !isRegisterOperand(instruction, 0, destination)) {
			return null;
		}
		Scalar scalar = scalarOperand(instruction, 1);
		if (scalar == null) {
			return null;
		}
		if (isMnemonic(instruction, "add")) {
			return scalar.getSignedValue();
		}
		if (isMnemonic(instruction, "sub") && scalar.getUnsignedValue() <= 0x7fff) {
			return -scalar.getUnsignedValue();
		}
		return null;
	}

	private static Long recoverGuardLow(Instruction instruction) {
		if (instruction == null || !isRegisterOperand(instruction, 0, "AL")) {
			return null;
		}
		Scalar scalar = scalarOperand(instruction, 1);
		if (scalar == null) {
			return null;
		}
		if (isMnemonic(instruction, "add") && scalar.getSignedValue() < 0) {
			return -scalar.getSignedValue();
		}
		if (isMnemonic(instruction, "sub") && scalar.getUnsignedValue() <= 0x7fff) {
			return scalar.getUnsignedValue();
		}
		return null;
	}

	private static boolean isMovzMemoryToAr6(Instruction instruction) {
		if (!isMnemonic(instruction, "movz") ||
			!isRegisterOperand(instruction, 0, "AR6") ||
			instruction.getNumOperands() != 2) {
			return false;
		}
		int type = instruction.getOperandType(1);
		return !OperandType.isRegister(type) &&
			(OperandType.isAddress(type) || OperandType.isIndirect(type) ||
				OperandType.isDynamic(type));
	}

	private static boolean isMovlMemoryToRegister(Instruction instruction,
			String registerName) {
		if (!isMnemonic(instruction, "movl") ||
			!isRegisterOperand(instruction, 0, registerName) ||
			instruction.getNumOperands() != 2) {
			return false;
		}
		return isMemoryOperand(instruction, 1);
	}

	private static boolean isMovAlFromMemory(Instruction instruction) {
		return isMnemonic(instruction, "mov") &&
			isRegisterOperand(instruction, 0, "AL") && instruction.getNumOperands() == 2 &&
			isMemoryOperand(instruction, 1);
	}

	private static boolean isImmediateDpLoad(Instruction instruction) {
		return isMnemonic(instruction, "movw") && instruction.getNumOperands() == 2 &&
			isRegisterOperand(instruction, 0, "DP") && scalarOperand(instruction, 1) != null;
	}

	private static boolean isMemoryStoreFromAl(Instruction instruction) {
		return isMnemonic(instruction, "mov") && instruction.getNumOperands() == 2 &&
			isMemoryOperand(instruction, 0) && isRegisterOperand(instruction, 1, "AL");
	}

	private static boolean isMemoryOperand(Instruction instruction, int operand) {
		if (instruction == null || operand >= instruction.getNumOperands()) {
			return false;
		}
		int type = instruction.getOperandType(operand);
		return !OperandType.isRegister(type) && !OperandType.isScalar(type) &&
			(OperandType.isAddress(type) || OperandType.isIndirect(type) ||
				OperandType.isDynamic(type));
	}

	private static boolean sameOperand(Instruction first, int firstOperand,
			Instruction second, int secondOperand) {
		if (first == null || second == null ||
			firstOperand >= first.getNumOperands() || secondOperand >= second.getNumOperands() ||
			!normalizeOperand(first, firstOperand).equals(normalizeOperand(second, secondOperand))) {
			return false;
		}
		Object[] firstObjects = first.getOpObjects(firstOperand);
		Object[] secondObjects = second.getOpObjects(secondOperand);
		if (firstObjects.length != secondObjects.length) {
			return false;
		}
		for (int index = 0; index < firstObjects.length; index++) {
			Object left = firstObjects[index];
			Object right = secondObjects[index];
			if (left instanceof Register leftRegister && right instanceof Register rightRegister) {
				if (!leftRegister.getName().equalsIgnoreCase(rightRegister.getName())) {
					return false;
				}
			}
			else if (left instanceof Scalar leftScalar && right instanceof Scalar rightScalar) {
				if (leftScalar.bitLength() != rightScalar.bitLength() ||
					leftScalar.getUnsignedValue() != rightScalar.getUnsignedValue()) {
					return false;
				}
			}
			else if (!left.equals(right)) {
				return false;
			}
		}
		return true;
	}

	private static String normalizeOperand(Instruction instruction, int operand) {
		return operandText(instruction, operand).replaceAll("\\s+", "").toUpperCase();
	}

	private static boolean isExactStackSelectorOperand(Instruction instruction, int operand) {
		String rendered = normalizeOperand(instruction, operand);
		if (!rendered.equals("*-SP[1]") && !rendered.equals("*-SP[0X1]")) {
			return false;
		}
		Object[] objects = instruction.getOpObjects(operand);
		return objects.length == 2 && objects[0] instanceof Register base &&
			base.getName().equalsIgnoreCase("SP") && objects[1] instanceof Scalar offset &&
			offset.getUnsignedValue() == 1;
	}

	private static Instruction recoverStackSelectorEntry(Program program, Instruction save) {
		if (isProvedFunctionEntry(program, save)) {
			return save;
		}

		Instruction allocation = contiguousPrevious(save);
		Scalar amount = scalarOperand(allocation, 1);
		if (!isMnemonic(allocation, "addb") ||
			!isRegisterOperand(allocation, 0, "SP") || amount == null ||
			amount.getUnsignedValue() != 2 ||
			!fallsThroughTo(allocation, save.getMinAddress()) ||
			hasExplicitFlowReferenceTo(save) ||
			!isProvedFunctionEntry(program, allocation)) {
			return null;
		}
		return allocation;
	}

	private static boolean isProvedFunctionEntry(Program program, Instruction instruction) {
		Address entry = instruction.getMinAddress();
		Function function = program.getFunctionManager().getFunctionContaining(entry);
		if (function != null && function.getEntryPoint().equals(entry)) {
			return true;
		}
		if (program.getSymbolTable().isExternalEntryPoint(entry)) {
			return true;
		}
		boolean callIngress = false;
		ReferenceIterator references = program.getReferenceManager().getReferencesTo(entry);
		while (references.hasNext()) {
			Reference reference = references.next();
			if (!reference.getReferenceType().isFlow()) {
				continue;
			}
			Instruction source = program.getListing().getInstructionAt(reference.getFromAddress());
			if (!reference.getReferenceType().isCall() || source == null ||
				!source.getFlowType().isCall() || !flowsTo(source, entry)) {
				return false;
			}
			callIngress = true;
		}
		Instruction previous = instruction.getPrevious();
		return callIngress &&
			(previous == null || !fallsThroughTo(previous, entry));
	}

	private static boolean isSetSxmOnly(Instruction instruction) {
		Scalar mask = scalarOperand(instruction, 0);
		return isMnemonic(instruction, "setc") && instruction.getNumOperands() == 1 &&
			mask != null && mask.getUnsignedValue() == 1;
	}

	private static boolean isClearSxmOnly(Instruction instruction) {
		Scalar mask = scalarOperand(instruction, 0);
		return isMnemonic(instruction, "clrc") && instruction.getNumOperands() == 1 &&
			mask != null && mask.getUnsignedValue() == 1;
	}

	private static SxmMode recoverSxmMode(Instruction instruction) {
		if (isSetSxmOnly(instruction)) {
			return SxmMode.SET;
		}
		return isClearSxmOnly(instruction) ? SxmMode.CLEAR : null;
	}

	private static boolean isAr6ScaledAdd(Instruction instruction) {
		Scalar shift = scalarOperand(instruction, 2);
		return isMnemonic(instruction, "add") &&
			isRegisterOperand(instruction, 0, "ACC") &&
			isRegisterOperand(instruction, 1, "AR6") && shift != null &&
			shift.getUnsignedValue() == 1;
	}

	private static boolean isImmediateAdd(Instruction instruction, String mnemonic,
			String destination, long value) {
		Scalar scalar = scalarOperand(instruction, 1);
		return isMnemonic(instruction, mnemonic) &&
			isRegisterOperand(instruction, 0, destination) && scalar != null &&
			scalar.getUnsignedValue() == value;
	}

	private static boolean isLslAccByOne(Instruction instruction) {
		Scalar shift = scalarOperand(instruction, 1);
		return isMnemonic(instruction, "lsl") &&
			isRegisterOperand(instruction, 0, "ACC") && shift != null &&
			shift.getUnsignedValue() == 1;
	}

	private static boolean isUnsignedConditionalBranch(Instruction instruction,
			String condition) {
		if (instruction == null || !instruction.getFlowType().isJump() ||
			!instruction.getFlowType().isConditional() ||
			!(isMnemonic(instruction, "sb") || isMnemonic(instruction, "b") ||
				isMnemonic(instruction, "bf"))) {
			return false;
		}
		return operandText(instruction, 1).equalsIgnoreCase(condition);
	}

	/**
	 * Return the one direct unconditional branch into a saved-selector compare.
	 * The proved firmware layouts place case bodies between the ingress branch
	 * and the dispatcher, so instruction adjacency is not part of the proof.
	 * Reject every second explicit flow edge and any implicit fall-through from
	 * the physically preceding instruction.
	 */
	private static Instruction soleDirectUnconditionalIngress(Instruction compare) {
		if (compare == null) {
			return null;
		}
		Instruction ingress = null;
		ReferenceIterator references = compare.getProgram().getReferenceManager()
			.getReferencesTo(compare.getMinAddress());
		while (references.hasNext()) {
			Reference reference = references.next();
			if (!reference.getReferenceType().isFlow()) {
				continue;
			}
			if (ingress != null) {
				return null;
			}
			Instruction source = compare.getProgram().getListing()
				.getInstructionAt(reference.getFromAddress());
			if (!isDirectUnconditionalBranchTo(source, compare.getMinAddress())) {
				return null;
			}
			ingress = source;
		}
		if (ingress == null) {
			return null;
		}

		Instruction physicalPrevious = compare.getPrevious();
		if (physicalPrevious != null && !physicalPrevious.equals(ingress) &&
			fallsThroughTo(physicalPrevious, compare.getMinAddress())) {
			return null;
		}
		return ingress;
	}

	private static boolean isDirectUnconditionalBranchTo(Instruction instruction,
			Address destination) {
		if (!isMnemonic(instruction, "b") || !instruction.getFlowType().isJump() ||
			instruction.getFlowType().isConditional()) {
			return false;
		}
		int operands = instruction.getNumOperands();
		if (operands != 1 &&
			(operands != 2 || !operandText(instruction, 1).equalsIgnoreCase("UNC"))) {
			return false;
		}
		Address[] flows = instruction.getFlows();
		return flows.length == 1 && flows[0].equals(destination);
	}

	private static Address unsignedGuardDefaultPath(Instruction guard,
			DispatchCandidate dispatch) {
		Address entry = dispatch.entryInstruction.getMinAddress();
		Address defaultPath;
		if (dispatch.variant != DispatchVariant.NATIVE_SAVED_P &&
			isUnsignedConditionalBranch(guard, "LOS") && flowsTo(guard, entry)) {
			defaultPath = guard.getFallThrough();
		}
		else if ((dispatch.variant == DispatchVariant.PROGRAM_READ_SAVED_LONG ||
			dispatch.variant == DispatchVariant.NATIVE_SAVED_LONG ||
			dispatch.variant == DispatchVariant.NATIVE_SAVED_LONG_SUBB ||
			dispatch.variant == DispatchVariant.NATIVE_SAVED_P ||
			dispatch.variant == DispatchVariant.NATIVE_AR6_ZERO ||
			dispatch.variant == DispatchVariant.NATIVE_AR6_SAVED_STACK) &&
			isUnsignedConditionalBranch(guard, "HI") &&
			fallsThroughTo(guard, entry)) {
			Address[] flows = guard.getFlows();
			if (flows.length != 1) {
				return null;
			}
			defaultPath = flows[0];
		}
		else {
			return null;
		}
		return defaultPath != null && !isWithinDispatch(defaultPath, dispatch)
				? defaultPath
				: null;
	}

	private static boolean isSelectorCopy(Instruction instruction) {
		return isRegisterMove(instruction, "mov", "AH", "AL") ||
			isRegisterMove(instruction, "mov", "AL", "AH");
	}

	private static boolean isRegisterMove(Instruction instruction, String mnemonic,
			String destination, String source) {
		return isMnemonic(instruction, mnemonic) &&
			isRegisterOperand(instruction, 0, destination) &&
			isRegisterOperand(instruction, 1, source);
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
		// Register-valued loc32 subtables may expose the operand as dynamic even
		// though the rendered operand and its sole object are the register itself.
		Object[] objects = instruction.getOpObjects(operand);
		return objects.length == 1 && objects[0] instanceof Register objectRegister &&
			objectRegister.getName().equalsIgnoreCase(registerName);
	}

	private static Scalar scalarOperand(Instruction instruction, int operand) {
		return instruction == null || operand >= instruction.getNumOperands()
				? null
				: instruction.getScalar(operand);
	}

	private static boolean writesRegister(Instruction instruction, String registerName) {
		if (instruction == null) {
			return false;
		}
		Register expected = instruction.getProgram().getLanguage().getRegister(registerName);
		if (expected != null) {
			for (Object object : instruction.getResultObjects()) {
				if (object instanceof Register result &&
					(expected.contains(result) || result.contains(expected))) {
					return true;
				}
			}
		}
		// Result objects are decoder-dependent; operand zero is a conservative
		// fallback for the XAR-writing instructions admitted by this recognizer.
		return isRegisterOperand(instruction, 0, registerName);
	}

	private static String operandText(Instruction instruction, int operand) {
		return instruction == null || operand >= instruction.getNumOperands()
				? ""
				: instruction.getDefaultOperandRepresentation(operand);
	}

	private static boolean flowsTo(Instruction instruction, Address destination) {
		if (instruction == null) {
			return false;
		}
		for (Address flow : instruction.getFlows()) {
			if (flow.equals(destination)) {
				return true;
			}
		}
		return false;
	}

	private static boolean fallsThroughTo(Instruction instruction, Address destination) {
		Address fallThrough = instruction == null ? null : instruction.getFallThrough();
		return fallThrough != null && fallThrough.equals(destination);
	}

	private static boolean hasExplicitFlowReferenceTo(Instruction instruction) {
		ReferenceIterator references = instruction.getProgram().getReferenceManager()
				.getReferencesTo(instruction.getMinAddress());
		while (references.hasNext()) {
			Reference reference = references.next();
			if (reference.getReferenceType().isFlow()) {
				return true;
			}
		}
		return false;
	}

	private static boolean isWithinDispatch(Address address, DispatchCandidate dispatch) {
		return address.compareTo(dispatch.entryInstruction.getMinAddress()) >= 0 &&
			address.compareTo(dispatch.branchInstruction.getMaxAddress()) <= 0;
	}

	private static Instruction contiguousPrevious(Instruction instruction) {
		if (instruction == null) {
			return null;
		}
		Instruction previous = instruction.getPrevious();
		return previous != null && previous.getMaxAddress().next().equals(instruction.getMinAddress())
				? previous
				: null;
	}

	private static Instruction contiguousNext(Instruction instruction) {
		if (instruction == null) {
			return null;
		}
		Instruction next = instruction.getNext();
		return next != null && instruction.getMaxAddress().next().equals(next.getMinAddress())
				? next
				: null;
	}

	/** Convert an architectural C28 word address to Ghidra's byte-offset Address. */
	private static Address wordAddress(Address basis, long wordOffset) {
		int wordSize = basis.getAddressSpace().getAddressableUnitSize();
		return basis.getAddressSpace().getAddress(Math.multiplyExact(wordOffset, wordSize));
	}

	private enum DispatchVariant {
		PROGRAM_READ("program-read PREAD", false, false),
		PROGRAM_READ_SAVED_LONG("saved-selector program-read PREAD", false, false),
		NATIVE_PL("unified-memory native-load", false, false),
		NATIVE_SAVED_LONG("saved-selector native-load", false, false),
		NATIVE_SAVED_LONG_SUBB("SUBB saved-selector native-load", false, false),
		NATIVE_SAVED_P("P-saved fall-through native-load", false, false),
		NATIVE_AR6_ZERO("zero-based AR6-indexed native-load", false, false),
		NATIVE_AR6_SAVED_GLOBAL("global saved-selector AR6 native-load", true, true),
		NATIVE_AR6_SAVED_STACK("stack saved-selector AR6 native-load", true, true),
		NATIVE_DIRECT("compact native-load", false, false);

		private final String description;
		private final boolean requiresPublication;
		private final boolean requiresOverride;

		DispatchVariant(String description, boolean requiresPublication,
				boolean requiresOverride) {
			this.description = description;
			this.requiresPublication = requiresPublication;
			this.requiresOverride = requiresOverride;
		}
	}

	private enum SxmMode {
		SET,
		CLEAR
	}

	private static final class IndexExpression {
		private final Instruction instruction;
		private final String sourceRegister;
		private final long scaleWords;
		private final long adjustmentWords;

		private IndexExpression(Instruction instruction, String sourceRegister, long scaleWords,
				long adjustmentWords) {
			this.instruction = instruction;
			this.sourceRegister = sourceRegister;
			this.scaleWords = scaleWords;
			this.adjustmentWords = adjustmentWords;
		}
	}

	private static final class DispatchCandidate {
		private final Instruction entryInstruction;
		private final Instruction branchInstruction;
		private final Address tableBase;
		private final IndexExpression indexExpression;
		private final DispatchVariant variant;

		private DispatchCandidate(Instruction entryInstruction, Instruction branchInstruction,
				Address tableBase, IndexExpression indexExpression, DispatchVariant variant) {
			this.entryInstruction = entryInstruction;
			this.branchInstruction = branchInstruction;
			this.tableBase = tableBase;
			this.indexExpression = indexExpression;
			this.variant = variant;
		}
	}

	private static final class Guard {
		private final Instruction instruction;
		@SuppressWarnings("unused")
		private final Instruction startInstruction;
		private final Instruction canonicalInstruction;
		private final long low;
		private final int count;
		private final Address defaultPath;
		private final DispatchVariant variant;

		private Guard(Instruction instruction, Instruction startInstruction,
				Instruction canonicalInstruction, long low, int count, Address defaultPath,
				DispatchVariant variant) {
			this.instruction = instruction;
			this.startInstruction = startInstruction;
			this.canonicalInstruction = canonicalInstruction;
			this.low = low;
			this.count = count;
			this.defaultPath = defaultPath;
			this.variant = variant;
		}
	}

	/** Fully recovered and validated switch facts shared by all dispatch variants. */
	private static final class SwitchDescriptor {
		private final Address branchAddress;
		private final Address tableBase;
		private final int count;
		private final long lowestCase;
		private final Address defaultPath;
		private final Instruction guardCanonicalInstruction;
		private final IndexExpression indexExpression;
		@SuppressWarnings("unused")
		private final List<Address> validatedTargets;
		private final DispatchVariant variant;
		private final Address provenFunctionEntry;

		private SwitchDescriptor(Address branchAddress, Address tableBase, int count,
				long lowestCase, Address defaultPath, Instruction guardCanonicalInstruction,
				IndexExpression indexExpression, List<Address> validatedTargets,
				DispatchVariant variant, Address provenFunctionEntry) {
			this.branchAddress = branchAddress;
			this.tableBase = tableBase;
			this.count = count;
			this.lowestCase = lowestCase;
			this.defaultPath = defaultPath;
			this.guardCanonicalInstruction = guardCanonicalInstruction;
			this.indexExpression = indexExpression;
			this.validatedTargets = validatedTargets;
			this.variant = variant;
			this.provenFunctionEntry = provenFunctionEntry;
		}
	}

	private static final class IndexAndTable {
		private final Instruction entryInstruction;
		private final Instruction indexInstruction;
		private final String indexSource;
		private final Instruction tableInstruction;
		private final Scalar tableScalar;

		private IndexAndTable(Instruction entryInstruction, Instruction indexInstruction,
				String indexSource, Instruction tableInstruction, Scalar tableScalar) {
			this.entryInstruction = entryInstruction;
			this.indexInstruction = indexInstruction;
			this.indexSource = indexSource;
			this.tableInstruction = tableInstruction;
			this.tableScalar = tableScalar;
		}
	}

	private static final class DirectIndexAndTable {
		private final Instruction entryInstruction;
		private final Instruction tableInstruction;
		private final Scalar tableScalar;
		private final Instruction indexInstruction;
		private final String indexSource;
		private final long adjustment;

		private DirectIndexAndTable(Instruction entryInstruction, Instruction tableInstruction,
				Scalar tableScalar, Instruction indexInstruction, String indexSource,
				long adjustment) {
			this.entryInstruction = entryInstruction;
			this.tableInstruction = tableInstruction;
			this.tableScalar = tableScalar;
			this.indexInstruction = indexInstruction;
			this.indexSource = indexSource;
			this.adjustment = adjustment;
		}
	}

	private static final class RegisterBound {
		private final Instruction instruction;
		private final long highInclusive;

		private RegisterBound(Instruction instruction, long highInclusive) {
			this.instruction = instruction;
			this.highInclusive = highInclusive;
		}
	}
}
