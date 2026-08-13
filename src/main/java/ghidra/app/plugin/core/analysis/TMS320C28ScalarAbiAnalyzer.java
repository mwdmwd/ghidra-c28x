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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.AbstractFloatDataType;
import ghidra.program.model.data.AbstractIntegerDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FloatDataType;
import ghidra.program.model.data.LongDataType;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * Applies the TI EABI's type-priority scalar allocation to explicitly typed functions.
 * <p>
 * Ghidra's standard parameter allocator walks parameters in declaration order.  The C28x
 * EABI instead reserves overlapping register classes by type priority: the first 64-bit
 * integer owns {@code ACC:P}, otherwise the first 32-bit integer owns {@code ACC}; pointers
 * reserve {@code XAR4/XAR5}; and only then do remaining 16-bit integers use the still-free
 * {@code AL}, {@code AH}, {@code AR4}, and {@code AR5} slots.  The compiler specification can
 * describe the legal {@code AL}/{@code AH}/{@code ACC} overlap for ordinary storage queries,
 * but dynamic HighFunction recovery still treats the containing accumulator as an exclusion
 * resource and can discard the independently typed {@code AH} parameter.  It also cannot
 * look ahead to enforce the ABI's type priority in the manual's mixed-order example.
 * <p>
 * This analyzer is deliberately gated on an imported or user-defined, fully supported scalar
 * prototype whose exact storage differs from the standard allocator, uses the ambiguous
 * {@code AH} slot, or contains a 64-bit integer argument or result.  It leaves untyped,
 * decompiler-inferred, variadic, and existing custom-storage functions untouched.  Stack
 * locations are delegated back to the function's selected prototype model after all register
 * pools are synthetically consumed, preserving the positive-growing word stack and the
 * distinct LCR, LC, and FFC first-argument offsets.
 */
public class TMS320C28ScalarAbiAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "TMS320C28 Typed Scalar ABI Analyzer";
	private static final String DESCRIPTION =
		"Applies exact TI EABI ACC:P and overlapping scalar-register storage to typed functions";
	private static final String PROCESSOR_NAME = "TMS320C28";

	private static final int SIZE_16 = 2;
	private static final int SIZE_32 = 4;
	private static final int SIZE_64 = 8;

	public TMS320C28ScalarAbiAnalyzer() {
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
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		FunctionIterator functions = program.getFunctionManager().getFunctions(set, true);
		while (functions.hasNext()) {
			monitor.checkCancelled();
			Function function = functions.next();
			if (function.isExternal() || function.isThunk() || function.hasCustomVariableStorage()) {
				continue;
			}
			SourceType source = function.getSignatureSource();
			if (source != SourceType.IMPORTED && source != SourceType.USER_DEFINED) {
				continue;
			}
			try {
				if (applyTypedScalarAbi(function)) {
					Msg.info(this, "applied typed scalar ABI storage at " +
						function.getEntryPoint());
				}
			}
			catch (InvalidInputException exception) {
				log.appendException(exception);
			}
		}
		return true;
	}

	/**
	 * Apply exact scalar storage to one naturally typed function.
	 *
	 * @param function function whose current non-auto parameters are the natural prototype
	 * @return true if the function required exact custom scalar storage and was updated
	 * @throws InvalidInputException if Ghidra rejects an otherwise supported storage map
	 */
	public static boolean applyTypedScalarAbi(Function function) throws InvalidInputException {
		if (function.hasCustomVariableStorage() || function.hasVarArgs()) {
			return false;
		}
		Program program = function.getProgram();
		List<Parameter> naturalParameters = new ArrayList<>();
		for (Parameter parameter : function.getParameters()) {
			if (!parameter.isAutoParameter()) {
				naturalParameters.add(parameter);
			}
		}

		ScalarKind returnKind = classify(function.getReturnType());
		ScalarKind[] parameterKinds = new ScalarKind[naturalParameters.size()];
		boolean hasLongLong = returnKind == ScalarKind.INTEGER_64;
		for (int i = 0; i < parameterKinds.length; i++) {
			parameterKinds[i] = classify(naturalParameters.get(i).getDataType());
			hasLongLong |= parameterKinds[i] == ScalarKind.INTEGER_64;
		}
		if (returnKind == ScalarKind.UNSUPPORTED ||
			Arrays.asList(parameterKinds).contains(ScalarKind.UNSUPPORTED) ||
			Arrays.asList(parameterKinds).contains(ScalarKind.VOID)) {
			return false; // never force a partial or misleading custom convention
		}

		RegisterSet registers = new RegisterSet(program);
		VariableStorage returnStorage = returnStorage(program, registers, returnKind);
		VariableStorage[] parameterStorage = allocateParameters(function, naturalParameters,
			parameterKinds, registers);
		if (!hasLongLong && !usesRegister(parameterStorage, registers.ah) &&
			matchesStandardStorage(function, naturalParameters, returnStorage, parameterStorage)) {
			return false;
		}

		ReturnParameterImpl returnParameter = new ReturnParameterImpl(function.getReturnType(),
			returnStorage, program);
		List<Variable> parameters = new ArrayList<>();
		for (int i = 0; i < naturalParameters.size(); i++) {
			Parameter old = naturalParameters.get(i);
			parameters.add(new ParameterImpl(old.getName(), old.getDataType(), parameterStorage[i],
				program));
		}
		String conventionName = selectedConventionName(function);
		try {
			function.updateFunction(conventionName, returnParameter, parameters,
				FunctionUpdateType.CUSTOM_STORAGE, true, function.getSignatureSource());
		}
		catch (DuplicateNameException exception) {
			throw new InvalidInputException(exception.getMessage());
		}
		return true;
	}

	private static boolean usesRegister(VariableStorage[] storage, Register register) {
		for (VariableStorage variableStorage : storage) {
			for (var varnode : variableStorage.getVarnodes()) {
				if (varnode.isRegister() && varnode.getAddress().equals(register.getAddress()) &&
					varnode.getSize() == register.getMinimumByteSize()) {
					return true;
				}
			}
		}
		return false;
	}

	private static boolean matchesStandardStorage(Function function,
			List<Parameter> parameters, VariableStorage returnStorage,
			VariableStorage[] parameterStorage) {
		PrototypeModel model = selectedPrototypeModel(function);
		List<DataType> types = new ArrayList<>();
		types.add(function.getReturnType());
		for (Parameter parameter : parameters) {
			types.add(parameter.getDataType());
		}
		VariableStorage[] standard = model.getStorageLocations(function.getProgram(),
			types.toArray(DataType[]::new), false);
		if (standard.length != parameterStorage.length + 1 ||
			!sameStorage(standard[0], returnStorage)) {
			return false;
		}
		for (int i = 0; i < parameterStorage.length; i++) {
			if (!sameStorage(standard[i + 1], parameterStorage[i])) {
				return false;
			}
		}
		return true;
	}

	private static boolean sameStorage(VariableStorage left, VariableStorage right) {
		return Arrays.equals(left.getVarnodes(), right.getVarnodes());
	}

	private static String selectedConventionName(Function function) {
		String name = function.getCallingConventionName();
		if (name == null || Function.UNKNOWN_CALLING_CONVENTION_STRING.equals(name) ||
			function.getProgram().getFunctionManager().getCallingConvention(name) == null) {
			return Function.DEFAULT_CALLING_CONVENTION_STRING;
		}
		return name;
	}

	private static PrototypeModel selectedPrototypeModel(Function function) {
		Program program = function.getProgram();
		PrototypeModel model = program.getFunctionManager().getCallingConvention(
			selectedConventionName(function));
		return model != null ? model : program.getCompilerSpec().getDefaultCallingConvention();
	}

	private static VariableStorage[] allocateParameters(Function function,
			List<Parameter> parameters, ScalarKind[] kinds, RegisterSet registers)
			throws InvalidInputException {
		Program program = function.getProgram();
		VariableStorage[] result = new VariableStorage[parameters.size()];

		int first64 = first(kinds, ScalarKind.INTEGER_64);
		int first32 = first(kinds, ScalarKind.INTEGER_32);
		boolean accumulatorReserved = first64 >= 0 || first32 >= 0;
		if (first64 >= 0) {
			result[first64] = registers.accP(program);
		}
		else if (first32 >= 0) {
			result[first32] = registers.storage(program, registers.acc);
		}

		Register[] pointerRegisters = { registers.xar4, registers.xar5 };
		int pointersUsed = 0;
		for (int i = 0; i < kinds.length && pointersUsed < pointerRegisters.length; i++) {
			if (kinds[i] == ScalarKind.POINTER) {
				result[i] = registers.storage(program, pointerRegisters[pointersUsed++]);
			}
		}

		Register[] floatRegisters = {
			registers.r0h, registers.r1h, registers.r2h, registers.r3h
		};
		int floatsUsed = 0;
		for (int i = 0; i < kinds.length && floatsUsed < floatRegisters.length; i++) {
			if (kinds[i] == ScalarKind.FLOAT_32) {
				result[i] = registers.storage(program, floatRegisters[floatsUsed++]);
			}
		}

		List<Register> available16 = new ArrayList<>();
		if (!accumulatorReserved) {
			available16.add(registers.al);
			available16.add(registers.ah);
		}
		if (pointersUsed == 0) {
			available16.add(registers.ar4);
		}
		if (pointersUsed <= 1) {
			available16.add(registers.ar5);
		}
		int scalar16Used = 0;
		for (int i = 0; i < kinds.length && scalar16Used < available16.size(); i++) {
			if (kinds[i] == ScalarKind.INTEGER_16) {
				result[i] = registers.storage(program, available16.get(scalar16Used++));
			}
		}

		List<Integer> stackIndexes = new ArrayList<>();
		List<DataType> stackTypes = new ArrayList<>();
		for (int i = 0; i < result.length; i++) {
			if (result[i] == null) {
				stackIndexes.add(i);
				stackTypes.add(parameters.get(i).getDataType());
			}
		}
		VariableStorage[] stackStorage = stackStorage(function, stackTypes);
		for (int i = 0; i < stackIndexes.size(); i++) {
			result[stackIndexes.get(i)] = stackStorage[i];
		}
		return result;
	}

	private static VariableStorage[] stackStorage(Function function, List<DataType> stackTypes)
			throws InvalidInputException {
		if (stackTypes.isEmpty()) {
			return new VariableStorage[0];
		}
		Program program = function.getProgram();
		PrototypeModel model = selectedPrototypeModel(function);
		DataTypeManager dtm = program.getDataTypeManager();
		DataType pointer = new PointerDataType(VoidDataType.dataType, dtm);
		DataType floating = new FloatDataType(dtm);
		DataType integer32 = new LongDataType(dtm);
		List<DataType> synthetic = new ArrayList<>();
		synthetic.add(VoidDataType.dataType); // result
		synthetic.add(pointer);
		synthetic.add(pointer);              // XAR4/XAR5
		for (int i = 0; i < 4; i++) {
			synthetic.add(floating);            // R0H-R3H
		}
		synthetic.add(integer32);            // ACC
		synthetic.addAll(stackTypes);
		VariableStorage[] all = model.getStorageLocations(program,
			synthetic.toArray(DataType[]::new), false);
		int firstStack = synthetic.size() - stackTypes.size();
		VariableStorage[] result = new VariableStorage[stackTypes.size()];
		for (int i = 0; i < result.length; i++) {
			VariableStorage storage = all[firstStack + i];
			if (!storage.hasStackStorage()) {
				throw new InvalidInputException(
					"failed to exhaust register pools before scalar stack allocation");
			}
			result[i] = storage;
		}
		return result;
	}

	private static VariableStorage returnStorage(Program program, RegisterSet registers,
			ScalarKind kind) throws InvalidInputException {
		return switch (kind) {
			case VOID -> VariableStorage.VOID_STORAGE;
			case INTEGER_16 -> registers.storage(program, registers.al);
			case INTEGER_32 -> registers.storage(program, registers.acc);
			case INTEGER_64 -> registers.accP(program);
			case POINTER -> registers.storage(program, registers.xar4);
			case FLOAT_32 -> registers.storage(program, registers.r0h);
			case UNSUPPORTED -> throw new InvalidInputException("unsupported scalar return type");
		};
	}

	private static int first(ScalarKind[] kinds, ScalarKind desired) {
		for (int i = 0; i < kinds.length; i++) {
			if (kinds[i] == desired) {
				return i;
			}
		}
		return -1;
	}

	private static ScalarKind classify(DataType dataType) {
		DataType base = dataType;
		while (base instanceof TypeDef typeDef) {
			base = typeDef.getBaseDataType();
		}
		if (base instanceof VoidDataType) {
			return ScalarKind.VOID;
		}
		if (base instanceof Pointer) {
			return base.getLength() == SIZE_32 ? ScalarKind.POINTER : ScalarKind.UNSUPPORTED;
		}
		if (base instanceof AbstractFloatDataType) {
			return base.getLength() == SIZE_32 ? ScalarKind.FLOAT_32 : ScalarKind.UNSUPPORTED;
		}
		if (base instanceof AbstractIntegerDataType) {
			return switch (base.getLength()) {
				case SIZE_16 -> ScalarKind.INTEGER_16;
				case SIZE_32 -> ScalarKind.INTEGER_32;
				case SIZE_64 -> ScalarKind.INTEGER_64;
				default -> ScalarKind.UNSUPPORTED;
			};
		}
		return ScalarKind.UNSUPPORTED;
	}

	private enum ScalarKind {
		VOID, INTEGER_16, INTEGER_32, INTEGER_64, POINTER, FLOAT_32, UNSUPPORTED
	}

	private static final class RegisterSet {
		final Register al;
		final Register ah;
		final Register acc;
		final Register p;
		final Register ar4;
		final Register ar5;
		final Register xar4;
		final Register xar5;
		final Register r0h;
		final Register r1h;
		final Register r2h;
		final Register r3h;

		RegisterSet(Program program) throws InvalidInputException {
			al = required(program, "AL", SIZE_16);
			ah = required(program, "AH", SIZE_16);
			acc = required(program, "ACC", SIZE_32);
			p = required(program, "P", SIZE_32);
			ar4 = required(program, "AR4", SIZE_16);
			ar5 = required(program, "AR5", SIZE_16);
			xar4 = required(program, "XAR4", SIZE_32);
			xar5 = required(program, "XAR5", SIZE_32);
			r0h = required(program, "R0H", SIZE_32);
			r1h = required(program, "R1H", SIZE_32);
			r2h = required(program, "R2H", SIZE_32);
			r3h = required(program, "R3H", SIZE_32);
		}

		VariableStorage storage(Program program, Register register) throws InvalidInputException {
			return new VariableStorage(program, register);
		}

		VariableStorage accP(Program program) throws InvalidInputException {
			return new VariableStorage(program, acc, p);
		}

		private static Register required(Program program, String name, int size)
				throws InvalidInputException {
			Register register = program.getRegister(name);
			if (register == null || register.getMinimumByteSize() != size) {
				throw new InvalidInputException("missing C28x register " + name + ":" + size);
			}
			return register;
		}
	}
}
