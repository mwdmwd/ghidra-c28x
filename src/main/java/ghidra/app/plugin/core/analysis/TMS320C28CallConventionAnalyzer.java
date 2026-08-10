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
import java.util.Locale;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * Assigns mechanism-specific prototype models only when a completed function
 * body proves its return sequence.
 * <p>
 * C28x has three ordinary long-call mechanisms with materially different link
 * state: LCR/LRETR uses RPC plus an old-RPC stack save, LC/LRET stores the
 * return PC directly on the stack, and FFC uses XAR7 with no stack/RPC save.
 * Instruction P-Code retains every architectural effect.  This analyzer merely
 * selects the matching compiler prototype so the decompiler inserts the right
 * completed-call effect in callers.
 * <p>
 * The FFC model is selected only for a terminal LB whose {@code ffc_return}
 * context was already established by {@link TMS320C28FfcReturnAnalyzer}.  The
 * LC model is selected only when every returning exit is LRET or LRETE and no
 * other terminal exit exists.  Mixed or unproved functions remain on the
 * default LCR/LRETR model.  Existing non-default operator/import conventions
 * are never overwritten.
 */
public class TMS320C28CallConventionAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "TMS320C28 Call Mechanism Analyzer";
	private static final String DESCRIPTION =
		"Selects LCR/RPC, LC/stack, or proven FFC/XAR7 prototype models";
	private static final String PROCESSOR_NAME = "TMS320C28";
	private static final String FFC_CONTEXT_NAME = "ffc_return";
	private static final String LC_CONVENTION = "__lc";
	private static final String FFC_CONVENTION = "__ffc";

	public TMS320C28CallConventionAnalyzer() {
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
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor,
			MessageLog log) throws CancelledException {
		Register ffcContext = program.getProgramContext().getRegister(FFC_CONTEXT_NAME);
		if (ffcContext == null) {
			log.appendMsg(NAME, "missing SLEIGH context register " + FFC_CONTEXT_NAME);
			return false;
		}
		if (program.getFunctionManager().getCallingConvention(LC_CONVENTION) == null ||
			program.getFunctionManager().getCallingConvention(FFC_CONVENTION) == null) {
			log.appendMsg(NAME, "missing compiler prototype __lc or __ffc");
			return false;
		}

		FunctionIterator functions = program.getFunctionManager().getFunctions(set, true);
		while (functions.hasNext()) {
			monitor.checkCancelled();
			Function function = functions.next();
			if (function.isExternal() || function.isThunk()) {
				continue;
			}
			String desired = classify(program, function, ffcContext, monitor);
			apply(function, desired, log);
		}
		return true;
	}

	private static String classify(Program program, Function function, Register ffcContext,
			TaskMonitor monitor) throws CancelledException {
		ReturnMechanism mechanism = null;
		int returns = 0;
		InstructionIterator instructions =
			program.getListing().getInstructions(function.getBody(), true);
		while (instructions.hasNext()) {
			monitor.checkCancelled();
			Instruction instruction = instructions.next();
			boolean hasReturn = hasPcode(instruction, PcodeOp.RETURN);
			if (!hasReturn && !instruction.getFlowType().isTerminal()) {
				continue;
			}
			if (!hasReturn) {
				return null; // terminal trap/tail exit: not a uniform returning function
			}
			ReturnMechanism current = mechanismFor(program, instruction, ffcContext);
			if (current == ReturnMechanism.OTHER) {
				return null;
			}
			if (mechanism != null && mechanism != current) {
				return null;
			}
			mechanism = current;
			returns++;
		}
		if (returns == 0) {
			return null;
		}
		if (mechanism == ReturnMechanism.FFC) {
			return FFC_CONVENTION;
		}
		if (mechanism == ReturnMechanism.LC) {
			return LC_CONVENTION;
		}
		return null; // LRETR/IRET/other proven return stays on default model
	}

	private static ReturnMechanism mechanismFor(Program program, Instruction instruction,
			Register ffcContext) {
		String mnemonic = instruction.getMnemonicString().toUpperCase(Locale.ROOT);
		if ("LB".equals(mnemonic) && BigInteger.ONE.equals(
			program.getProgramContext().getValue(ffcContext,
				instruction.getMinAddress(), false))) {
			return ReturnMechanism.FFC;
		}
		if ("LRET".equals(mnemonic) || "LRETE".equals(mnemonic)) {
			return ReturnMechanism.LC;
		}
		if ("LRETR".equals(mnemonic)) {
			return ReturnMechanism.LCR;
		}
		if ("IRET".equals(mnemonic)) {
			return ReturnMechanism.INTERRUPT;
		}
		return ReturnMechanism.OTHER;
	}

	private static boolean hasPcode(Instruction instruction, int opcode) {
		for (PcodeOp op : instruction.getPcode()) {
			if (op.getOpcode() == opcode) {
				return true;
			}
		}
		return false;
	}

	private static void apply(Function function, String desired, MessageLog log) {
		String current = function.getCallingConventionName();
		boolean ours = LC_CONVENTION.equals(current) || FFC_CONVENTION.equals(current);
		boolean ordinary = function.hasUnknownCallingConventionName() ||
			Function.DEFAULT_CALLING_CONVENTION_STRING.equals(current);
		try {
			if (desired != null) {
				if (!ordinary && !ours) {
					return; // preserve imported/operator convention
				}
				if (!desired.equals(current)) {
					function.setCallingConvention(desired);
					Msg.info(TMS320C28CallConventionAnalyzer.class,
						"selected " + desired + " for " + function.getEntryPoint());
				}
			}
			else if (ours) {
				function.setCallingConvention(Function.UNKNOWN_CALLING_CONVENTION_STRING);
				Msg.info(TMS320C28CallConventionAnalyzer.class,
					"revoked unproved call mechanism at " + function.getEntryPoint());
			}
		}
		catch (InvalidInputException exception) {
			log.appendException(exception);
		}
	}

	private enum ReturnMechanism {
		LCR, LC, FFC, INTERRUPT, OTHER
	}
}
