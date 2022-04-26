// Copyright (c) zkMove Authors

use crate::value::Value;
use crate::vm_circuit::chips::bytecode::{convert_to_fields, Opcode};
use crate::vm_circuit::chips::lookup_tables::RWTarget;
use halo2_proofs::arithmetic::FieldExt;
use move_binary_format::file_format::{
    Bytecode, CompiledModuleMut, CompiledScript, CompiledScriptMut,
};
use move_binary_format::CompiledModule;
use std::cmp::Ordering;
use std::convert::From;
use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionStep<F: FieldExt> {
    pub opcode: Opcode,
    pub pc: u16,
    pub stack_size: usize,
    pub call_index: usize,
    pub locals_index: usize,
    pub gc: usize, // global counter for stack, locals, state accesses
    pub module_index: u16,
    pub function_index: u16,
    pub auxiliary: Option<Value<F>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RW {
    READ = 0,
    WRITE,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalsOp<F: FieldExt> {
    pub call_index: usize, // locals ops will sorted by (call_index, index, gc)
    pub index: usize,
    pub gc: usize,
    pub rw: RW,
    pub value: Value<F>,
}

impl<F: FieldExt> PartialOrd for LocalsOp<F> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<F: FieldExt> Ord for LocalsOp<F> {
    fn cmp(&self, other: &Self) -> Ordering {
        (&self.call_index, &self.index, &self.gc).cmp(&(&other.call_index, &other.index, &other.gc))
    }
}

// convert LocalsOp into a vector of field value
impl<F: FieldExt> From<&LocalsOp<F>> for Vec<Option<F>> {
    fn from(rw_op: &LocalsOp<F>) -> Vec<Option<F>> {
        let mut field_values = Vec::new();
        field_values.push(Some(F::from_u128(rw_op.gc as u128)));
        field_values.push(Some(F::from_u128(RWTarget::Locals as u128)));
        field_values.push(Some(F::from_u128(rw_op.rw.clone() as u128)));
        field_values.push(Some(F::from_u128(rw_op.call_index as u128)));
        field_values.push(Some(F::from_u128(rw_op.index as u128)));

        let value = match rw_op.value {
            Value::Invalid => Some(F::zero()), // todo: how to distinguish with Value::Constant(0)
            _ => rw_op.value.value(),
        };
        field_values.push(value);
        field_values
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StackOp<F: FieldExt> {
    pub address: usize, // stack ops will be sorted by (address, gc)
    pub gc: usize,
    pub rw: RW,
    pub value: Value<F>,
}

impl<F: FieldExt> PartialOrd for StackOp<F> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<F: FieldExt> Ord for StackOp<F> {
    fn cmp(&self, other: &Self) -> Ordering {
        (&self.address, &self.gc).cmp(&(&other.address, &other.gc))
    }
}

// convert StackOp into a vector of field value
impl<F: FieldExt> From<&StackOp<F>> for Vec<Option<F>> {
    fn from(rw_op: &StackOp<F>) -> Vec<Option<F>> {
        let mut field_values = Vec::new();
        field_values.push(Some(F::from_u128(rw_op.gc as u128)));
        field_values.push(Some(F::from_u128(RWTarget::Stack as u128)));
        field_values.push(Some(F::from_u128(rw_op.rw.clone() as u128)));
        field_values.push(Some(F::from_u128(0)));
        field_values.push(Some(F::from_u128(rw_op.address as u128)));

        let value = match rw_op.value {
            Value::Invalid => Some(F::zero()), // todo: how to distinguish with Value::Constant(0)
            _ => rw_op.value.value(),
        };
        field_values.push(value);
        field_values
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RWOperation<F: FieldExt> {
    LocalsOp(LocalsOp<F>),
    StackOp(StackOp<F>),
}

impl<F: FieldExt> RWOperation<F> {
    pub fn is_stack_op(&self) -> bool {
        match self {
            Self::StackOp(_) => true,
            _ => false,
        }
    }

    pub fn is_locals_op(&self) -> bool {
        match self {
            Self::LocalsOp(_) => true,
            _ => false,
        }
    }

    pub fn gc(&self) -> usize {
        match self {
            Self::StackOp(op) => op.gc,
            Self::LocalsOp(op) => op.gc,
        }
    }

    pub fn rw_target(&self) -> RWTarget {
        match self {
            Self::StackOp(_) => RWTarget::Stack,
            Self::LocalsOp(_) => RWTarget::Locals,
        }
    }

    pub fn rw(&self) -> RW {
        match self {
            Self::StackOp(op) => op.rw.clone(),
            Self::LocalsOp(op) => op.rw.clone(),
        }
    }

    pub fn call_index(&self) -> usize {
        match self {
            Self::StackOp(_) => 0,
            Self::LocalsOp(op) => op.call_index,
        }
    }

    pub fn address(&self) -> usize {
        match self {
            Self::StackOp(op) => op.address,
            Self::LocalsOp(op) => op.index,
        }
    }

    pub fn value(&self) -> Value<F> {
        match self {
            Self::StackOp(op) => op.value.clone(),
            Self::LocalsOp(op) => op.value.clone(),
        }
    }
}

// convert RWOperation into a vector of field value
impl<F: FieldExt> From<&RWOperation<F>> for Vec<Option<F>> {
    fn from(rw_op: &RWOperation<F>) -> Vec<Option<F>> {
        let mut field_values = Vec::new();
        field_values.push(Some(F::from_u128(rw_op.gc() as u128)));
        field_values.push(Some(F::from_u128(rw_op.rw_target() as u128)));
        field_values.push(Some(F::from_u128(rw_op.rw() as u128)));
        field_values.push(Some(F::from_u128(rw_op.call_index() as u128)));
        field_values.push(Some(F::from_u128(rw_op.address() as u128)));

        let value = match rw_op.value() {
            Value::Invalid => Some(F::zero()), // todo: how to distinguish with Value::Constant(0)
            _ => rw_op.value().value(),
        };
        field_values.push(value);
        field_values
    }
}

#[derive(Clone, Debug, Default)]
pub struct RWLookUpTable<F: FieldExt>(pub Vec<RWOperation<F>>);

impl<F: FieldExt> From<RWLookUpTable<F>> for (SortedStackOps<F>, SortedLocalsOps<F>) {
    fn from(rw_table: RWLookUpTable<F>) -> (SortedStackOps<F>, SortedLocalsOps<F>) {
        let mut stack_ops = Vec::new();
        let mut locals_ops = Vec::new();
        rw_table.0.into_iter().for_each(|op| match op {
            RWOperation::StackOp(stack_op) => stack_ops.push(stack_op),
            RWOperation::LocalsOp(locals_op) => locals_ops.push(locals_op),
        });
        stack_ops.sort();
        locals_ops.sort();
        (SortedStackOps(stack_ops), SortedLocalsOps(locals_ops))
    }
}

#[derive(Clone, Debug, Default)]
pub struct SortedStackOps<F: FieldExt>(pub Vec<StackOp<F>>);

// convert SortedStackOps into field values
impl<F: FieldExt> From<&SortedStackOps<F>> for Vec<Vec<Option<F>>> {
    fn from(rw_ops: &SortedStackOps<F>) -> Vec<Vec<Option<F>>> {
        rw_ops.0.iter().map(|op| op.into()).collect()
    }
}

#[derive(Clone, Debug, Default)]
pub struct SortedLocalsOps<F: FieldExt>(pub Vec<LocalsOp<F>>);

// convert SortedLocalsOps into field values
impl<F: FieldExt> From<&SortedLocalsOps<F>> for Vec<Vec<Option<F>>> {
    fn from(rw_ops: &SortedLocalsOps<F>) -> Vec<Vec<Option<F>>> {
        rw_ops.0.iter().map(|op| op.into()).collect()
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct BytecodeInfo {
    module_index: u16,
    function_index: u16,
    pc: u16,
    bytecode: Bytecode,
}

impl Default for BytecodeInfo {
    fn default() -> Self {
        Self::new(0, 0, 0, Bytecode::Nop)
    }
}

impl BytecodeInfo {
    pub fn new(module_index: u16, function_index: u16, pc: u16, bytecode: Bytecode) -> Self {
        BytecodeInfo {
            module_index,
            function_index,
            pc,
            bytecode,
        }
    }
}

// convert BytecodeInfo into a vector of field values
impl<F: FieldExt> From<&BytecodeInfo> for Vec<F> {
    fn from(bytecode_info: &BytecodeInfo) -> Vec<F> {
        let mut field_values = Vec::new();
        field_values.push(F::from_u128(bytecode_info.module_index as u128));
        field_values.push(F::from_u128(bytecode_info.function_index as u128));
        field_values.push(F::from_u128(bytecode_info.pc as u128));

        let (opcode, operand) = convert_to_fields(bytecode_info.bytecode.clone());
        field_values.push(opcode);
        field_values.push(operand);

        field_values
    }
}

#[derive(Clone, Default, PartialEq, Debug)]
pub struct BytecodeTable(Vec<BytecodeInfo>);

impl BytecodeTable {
    pub fn new(bytecodes: Vec<BytecodeInfo>) -> Self {
        Self(bytecodes)
    }
    pub fn as_inner(&self) -> &Vec<BytecodeInfo> {
        &self.0
    }
    pub fn into_inner(self) -> Vec<BytecodeInfo> {
        self.0
    }
}

// convert BytecodeTable into a vector of vector of field values
impl<F: FieldExt> From<&BytecodeTable> for Vec<Vec<F>> {
    fn from(bytecode_table: &BytecodeTable) -> Vec<Vec<F>> {
        bytecode_table
            .0
            .iter()
            .map(|bytecode_info| bytecode_info.into())
            .collect()
    }
}

impl From<CompiledScriptMut> for BytecodeTable {
    fn from(script: CompiledScriptMut) -> BytecodeTable {
        BytecodeTable(
            script
                .code
                .code
                .iter()
                .enumerate()
                .map(|(i, bytecode)| BytecodeInfo::new(0, 0, i as u16, bytecode.clone()))
                .collect(),
        )
    }
}

impl From<Vec<CompiledModuleMut>> for BytecodeTable {
    fn from(modules: Vec<CompiledModuleMut>) -> BytecodeTable {
        let mut bytecodes = Vec::new();
        for (index, module) in modules.iter().enumerate() {
            let module_index = index + 1;
            for func_def in module.function_defs.iter() {
                if let Some(code_unit) = func_def.code.clone() {
                    let mut func_bytecodes = code_unit
                        .code
                        .iter()
                        .enumerate()
                        .map(|(i, bytecode)| {
                            BytecodeInfo::new(
                                module_index as u16,
                                func_def.function.0,
                                i as u16,
                                bytecode.clone(),
                            )
                        })
                        .collect();
                    bytecodes.append(&mut func_bytecodes);
                }
            }
        }
        BytecodeTable(bytecodes)
    }
}

impl From<(CompiledScriptMut, Vec<CompiledModuleMut>)> for BytecodeTable {
    fn from((script, modules): (CompiledScriptMut, Vec<CompiledModuleMut>)) -> BytecodeTable {
        let script_bytecodes = BytecodeTable::from(script);
        let modules_bytecodes = BytecodeTable::from(modules);
        let mut bytecodes = Vec::new();
        bytecodes.append(&mut script_bytecodes.into_inner());
        bytecodes.append(&mut modules_bytecodes.into_inner());
        BytecodeTable(bytecodes)
    }
}

impl From<(CompiledScript, Vec<CompiledModule>)> for BytecodeTable {
    fn from((script, modules): (CompiledScript, Vec<CompiledModule>)) -> BytecodeTable {
        let modules_into_inner = modules
            .into_iter()
            .map(|module| module.into_inner())
            .collect();
        (script.into_inner(), modules_into_inner).into()
    }
}

#[derive(Clone, Default)]
pub struct CircuitInputs<F: FieldExt> {
    pub exec_steps: Vec<ExecutionStep<F>>,
    pub rw_lookup_table: RWLookUpTable<F>,
    pub sorted_stack_ops: SortedStackOps<F>,
    pub sorted_locals_ops: SortedLocalsOps<F>,
    pub bytecode_table: BytecodeTable,
}

impl<F: FieldExt> CircuitInputs<F> {
    pub fn new(
        exec_steps: Vec<ExecutionStep<F>>,
        rw_lookup_table: RWLookUpTable<F>,
        bytecode_table: BytecodeTable,
    ) -> Self {
        let (sorted_stack_ops, sorted_locals_ops) = rw_lookup_table.clone().into();
        CircuitInputs {
            exec_steps,
            rw_lookup_table,
            sorted_stack_ops,
            sorted_locals_ops,
            bytecode_table,
        }
    }
}

impl<F: FieldExt> fmt::Debug for CircuitInputs<F> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "\n")?;
        write!(f, "Execution steps:\n")?;
        self.exec_steps.iter().enumerate().for_each(|(i, step)| {
            write!(f, "{}: {:?}\n", i, step).unwrap();
        });
        write!(f, "\n")?;
        write!(f, "Read/Write operations:\n")?;
        self.rw_lookup_table.0.iter().for_each(|op| {
            write!(f, "{:?}\n", op).unwrap();
        });
        write!(f, "\n")?;
        write!(f, "Sorted stack operations:\n")?;
        self.sorted_stack_ops.0.iter().for_each(|op| {
            write!(f, "{:?}\n", op).unwrap();
        });
        write!(f, "\n")?;
        write!(f, "Sorted locals operations:\n")?;
        self.sorted_locals_ops.0.iter().for_each(|op| {
            write!(f, "{:?}\n", op).unwrap();
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::vm_circuit::circuit_inputs::{BytecodeInfo, BytecodeTable};
    use error::VmResult;
    use move_binary_format::file_format::{
        empty_module, empty_script, Bytecode, CodeUnit, CompiledModuleMut, CompiledScriptMut,
        FunctionDefinition, FunctionHandle, FunctionHandleIndex, IdentifierIndex,
        ModuleHandleIndex, SignatureIndex, Visibility,
    };
    use move_core_types::identifier::Identifier;

    // module {
    //     foo() {
    //     }
    // }
    fn test_module() -> CompiledModuleMut {
        let mut m = empty_module();

        m.function_handles.push(FunctionHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(m.identifiers.len() as u16),
            parameters: SignatureIndex(0),
            return_: SignatureIndex(0),
            type_parameters: vec![],
        });
        m.identifiers
            .push(Identifier::new("foo".to_string()).unwrap());

        m.function_defs.push(FunctionDefinition {
            function: FunctionHandleIndex(0),
            visibility: Visibility::Private,
            acquires_global_resources: vec![],
            code: Some(CodeUnit {
                locals: SignatureIndex(0),
                code: vec![Bytecode::Ret],
            }),
        });
        m
    }

    fn test_script() -> CompiledScriptMut {
        let mut script = empty_script();
        script.code.code = vec![
            Bytecode::LdU64(1u64),
            Bytecode::LdU64(2u64),
            Bytecode::Add,
            Bytecode::Pop,
            Bytecode::Ret,
        ];
        script
    }

    #[test]
    fn test_bytecode_table() -> VmResult<()> {
        logger::init_for_test();

        let script = test_script();
        let module = test_module();
        let bytecodes = BytecodeTable::from((script.clone(), vec![module]));

        let expected_bytecode_table = BytecodeTable(vec![
            BytecodeInfo::new(0, 0, 0, Bytecode::LdU64(1u64)),
            BytecodeInfo::new(0, 0, 1, Bytecode::LdU64(2u64)),
            BytecodeInfo::new(0, 0, 2, Bytecode::Add),
            BytecodeInfo::new(0, 0, 3, Bytecode::Pop),
            BytecodeInfo::new(0, 0, 4, Bytecode::Ret),
            BytecodeInfo::new(1, 0, 0, Bytecode::Ret),
        ]);

        assert_eq!(bytecodes, expected_bytecode_table, "result is not expected");
        Ok(())
    }
}
