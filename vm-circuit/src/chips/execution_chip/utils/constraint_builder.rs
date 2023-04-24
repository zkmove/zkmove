use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::step_chip::StepConfig;
use crate::chips::execution_chip::utils::CellType;
use crate::chips::utilities::Cell;
use halo2_proofs::{arithmetic::FieldExt, plonk::Expression};

// Max degree allowed in all expressions passing through the ConstraintBuilder.
// It aims to cap `extended_k` to 2, which allows constraint degree to 2^2+1,
// but each InstructionGadget has implicit selector degree 3, so here it only
// allows 2^2+1-3 = 2.
//const MAX_DEGREE: usize = 5;
//const IMPLICIT_DEGREE: usize = 3;

/*
pub(crate) enum Transition<T> {
    Same,
    Delta(T),
    // To(T),
    // Any,
}

impl<F> Default for Transition<F> {
    fn default() -> Self {
        Self::Same
    }
}
#[derive(Default)]
pub(crate) struct StepStateTransition<F: Field> {
    pub(crate) rw_counter: Transition<Expression<F>>,
    pub(crate) call_id: Transition<Expression<F>>,
    pub(crate) is_root: Transition<Expression<F>>,
    pub(crate) is_create: Transition<Expression<F>>,
    pub(crate) code_hash: Transition<Expression<F>>,
    pub(crate) program_counter: Transition<Expression<F>>,
    pub(crate) stack_pointer: Transition<Expression<F>>,
    pub(crate) gas_left: Transition<Expression<F>>,
    pub(crate) memory_word_size: Transition<Expression<F>>,
    pub(crate) reversible_write_counter: Transition<Expression<F>>,
    pub(crate) log_id: Transition<Expression<F>>,
}

impl<F: Field> StepStateTransition<F> {
    pub(crate) fn new_context() -> Self {
        Self {
            program_counter: Transition::To(0.expr()),
            stack_pointer: Transition::To(STACK_CAPACITY.expr()),
            memory_word_size: Transition::To(0.expr()),
            ..Default::default()
        }
    }

    pub(crate) fn any() -> Self {
        Self {
            rw_counter: Transition::Any,
            call_id: Transition::Any,
            is_root: Transition::Any,
            is_create: Transition::Any,
            code_hash: Transition::Any,
            program_counter: Transition::Any,
            stack_pointer: Transition::Any,
            gas_left: Transition::Any,
            memory_word_size: Transition::Any,
            reversible_write_counter: Transition::Any,
            log_id: Transition::Any,
        }
    }
}

    pub condition: Option<Expression<F>>,
}

impl<F: Field> BaseConstraintBuilder<F> {
    pub(crate) fn new(max_degree: usize) -> Self {
        BaseConstraintBuilder {
            constraints: Vec::new(),
            max_degree,
            condition: None,
        }
    }

    pub(crate) fn require_zero(&mut self, name: &'static str, constraint: Expression<F>) {
        self.add_constraint(name, constraint);
    }

    pub(crate) fn require_equal(
        &mut self,
        name: &'static str,
        lhs: Expression<F>,
        rhs: Expression<F>,
    ) {
        self.add_constraint(name, lhs - rhs);
    }

    pub(crate) fn require_boolean(&mut self, name: &'static str, value: Expression<F>) {
        self.add_constraint(name, value.clone() * (1.expr() - value));
    }

    pub(crate) fn require_in_set(
        &mut self,
        name: &'static str,
        value: Expression<F>,
        set: Vec<Expression<F>>,
    ) {
        self.add_constraint(
            name,
            set.iter()
                .fold(1.expr(), |acc, item| acc * (value.clone() - item.clone())),
        );
    }

    pub(crate) fn condition<R>(
        &mut self,
        condition: Expression<F>,
        constraint: impl FnOnce(&mut Self) -> R,
    ) -> R {
        debug_assert!(
            self.condition.is_none(),
            "Nested condition is not supported"
        );
        self.condition = Some(condition);
        let ret = constraint(self);
        self.condition = None;
        ret
    }

    pub(crate) fn add_constraints(&mut self, constraints: Vec<(&'static str, Expression<F>)>) {
        for (name, constraint) in constraints {
            self.add_constraint(name, constraint);
        }
    }

    pub(crate) fn add_constraint(&mut self, name: &'static str, constraint: Expression<F>) {
        let constraint = match &self.condition {
            Some(condition) => condition.clone() * constraint,
            None => constraint,
        };
        self.validate_degree(constraint.degree(), name);
        self.constraints.push((name, constraint));
    }

    pub(crate) fn validate_degree(&self, degree: usize, name: &'static str) {
        if self.max_degree > 0 {
            debug_assert!(
                degree <= self.max_degree,
                "Expression {} degree too high: {} > {}",
                name,
                degree,
                self.max_degree,
            );
        }
    }

    pub(crate) fn gate(&self, selector: Expression<F>) -> Vec<(&'static str, Expression<F>)> {
        self.constraints
            .clone()
            .into_iter()
            .map(|(name, constraint)| (name, selector.clone() * constraint))
            .filter(|(name, constraint)| {
                self.validate_degree(constraint.degree(), name);
                true
            })
            .collect()
    }
}

*/

pub(crate) struct ConstraintBuilder<F: FieldExt> {
    // pub max_degree: usize,
    // pub(crate) step_config: &StepConfig<F>,
    pub(crate) curr: StepConfig<F>,
    pub(crate) next: StepConfig<F>,
    // power_of_randomness: &'a [Expression<F>; 31],
    constraints: Vec<(&'static str, Expression<F>)>,
    // rw_counter_offset: Expression<F>,
    // program_counter_offset: usize,
    // stack_pointer_offset: Expression<F>,
    // log_id_offset: usize,
    in_next_step: bool,
    // condition: Option<Expression<F>>,
    // constraints_location: ConstraintLocation,
    // stored_expressions: Vec<StoredExpression<F>>,
}

impl<'a, F: FieldExt> ConstraintBuilder<F> {
    pub(crate) fn new(curr: StepConfig<F>, next: StepConfig<F>, _opcode: Opcode) -> Self {
        Self {
            curr,
            next,
            constraints: Vec::new(),
            in_next_step: false,
        }
    }

    /// Returns (list of constraints, list of first step constraints, stored
    /// expressions, height used).
    #[allow(clippy::type_complexity)]
    pub(crate) fn build(self) -> (Vec<(&'static str, Expression<F>)>, usize) {
        // let exec_state_sel = self.step_config.conditions_selector(self.opcode);
        // let mul_exec_state_sel = |c: Vec<(&'static str, Expression<F>)>| {
        //     c.into_iter()
        //         .map(|(name, constraint)| (name, exec_state_sel.clone() * constraint))
        //         .collect()
        // };
        (
            //mul_exec_state_sel(self.constraints),
            self.constraints,
            self.curr.cell_allocator.get_height(),
        )
    }

    /*
    pub(crate) fn opcode_get(&self) -> Opcode {
        self.opcode
    }

    // Query

    pub(crate) fn copy<E: Expr<F>>(&mut self, value: E) -> Cell<F> {
        let cell = self.query_cell();
        self.require_equal("Copy value to new cell", cell.expression.clone(), value.expr());
        cell
    }

    pub(crate) fn query_bool(&mut self) -> Cell<F> {
        let cell = self.query_cell();
        self.require_boolean("Constrain cell to be a bool", cell.expression.clone());
        cell
    }
    */
    pub(crate) fn query_cell(&mut self) -> Cell<F> {
        self.query_cell_with_type(CellType::CustomGate)
    }

    pub(crate) fn query_n_cells(&mut self, count: usize) -> Vec<Cell<F>> {
        self.query_cells(CellType::CustomGate, count)
    }
    /*
    pub(crate) fn query_copy_cell(&mut self) -> Cell<F> {
        self.query_cell_with_type(CellType::StoragePermutation)
    }
    */
    pub(crate) fn query_cell_with_type(&mut self, cell_type: CellType) -> Cell<F> {
        self.query_cells(cell_type, 1).first().unwrap().clone()
    }

    fn query_cells(&mut self, cell_type: CellType, count: usize) -> Vec<Cell<F>> {
        if self.in_next_step {
            &mut self.next
        } else {
            &mut self.curr
        }
        .cell_allocator
        .query_cells(cell_type, count)
    }

    // Common

    /*
    pub(crate) fn require_zero(&mut self, name: &'static str, constraint: Expression<F>) {
        self.add_constraint(name, constraint);
    }

    pub(crate) fn require_equal(
        &mut self,
        name: &'static str,
        lhs: Expression<F>,
        rhs: Expression<F>,
    ) {
        self.add_constraint(name, lhs - rhs);
    }

    pub(crate) fn require_boolean(&mut self, name: &'static str, value: Expression<F>) {
        self.add_constraint(name, value.clone() * (1.expr() - value));
    }

    pub(crate) fn require_in_set(
        &mut self,
        name: &'static str,
        value: Expression<F>,
        set: Vec<Expression<F>>,
    ) {
        self.add_constraint(
            name,
            set.iter()
                .fold(1.expr(), |acc, item| acc * (value.clone() - item.clone())),
        );
    }

    pub(crate) fn require_next_state(&mut self, opcode: Opcode) {
        let next_state = self.next.execution_state_selector(opcode);
        self.add_constraint(
            "Constrain next execution state",
            1.expr() - next_state.expr(),
        );
    }

    pub(crate) fn require_next_state_not(&mut self, opcode: Opcode) {
        let next_state = self.next.execution_state_selector(opcode);
        self.add_constraint("Constrain next execution state not", next_state.expr());
    }

    // Fixed

    // look up opcode's min and max stack pointer
    pub(crate) fn opcode_stack_lookup(
        &mut self,
        opcode: Expression<F>,
        min_stack: Expression<F>,
        max_stack: Expression<F>,
    ) {
        self.add_lookup(
            "op code stack info",
            Lookup::Fixed {
                tag: FixedTableTag::OpcodeStack.expr(),
                values: [opcode, min_stack, max_stack],
            },
        );
    }

    // Opcode

    pub(crate) fn opcode_lookup(&mut self, opcode: Expression<F>, is_code: Expression<F>) {
        self.opcode_lookup_at(
            self.curr.state.program_counter.expr() + self.program_counter_offset.expr(),
            opcode,
            is_code,
        );
        self.program_counter_offset += 1;
    }

    pub(crate) fn opcode_lookup_at(
        &mut self,
        index: Expression<F>,
        opcode: Expression<F>,
        is_code: Expression<F>,
    ) {
        let is_root_create = self.curr.state.is_root.expr() * self.curr.state.is_create.expr();
        self.add_lookup(
            "Opcode lookup",
            Lookup::Bytecode {
                hash: self.curr.state.code_hash.expr(),
                tag: BytecodeFieldTag::Byte.expr(),
                index,
                is_code,
                value: opcode,
            }
            .conditional(1.expr() - is_root_create),
        );
    }

    // Bytecode table

    pub(crate) fn bytecode_lookup(
        &mut self,
        code_hash: Expression<F>,
        index: Expression<F>,
        is_code: Expression<F>,
        value: Expression<F>,
    ) {
        self.add_lookup(
            "Bytecode (byte) lookup",
            Lookup::Bytecode {
                hash: code_hash,
                tag: BytecodeFieldTag::Byte.expr(),
                index,
                is_code,
                value,
            },
        )
    }

    pub(crate) fn bytecode_length(&mut self, code_hash: Expression<F>) -> Cell<F> {
        let cell = self.query_cell();
        self.add_lookup(
            "Bytecode (length)",
            Lookup::Bytecode {
                hash: code_hash,
                tag: BytecodeFieldTag::Length.expr(),
                index: 0.expr(),
                is_code: 0.expr(),
                value: cell.expr(),
            },
        );
        cell
    }

    // Rw

    /// Add a Lookup::Rw without increasing the rw_counter_offset, which is
    /// useful for state reversion or dummy lookup.
    fn rw_lookup_with_counter(
        &mut self,
        name: &str,
        counter: Expression<F>,
        is_write: Expression<F>,
        tag: RwTableTag,
        values: RwValues<F>,
    ) {
        let name = format!("rw lookup {}", name);
        self.add_lookup(
            &name,
            Lookup::Rw {
                counter,
                is_write,
                tag: tag.expr(),
                values,
            },
        );
    }

    /// Add a Lookup::Rw and increase the rw_counter_offset, useful in normal
    /// cases.
    fn rw_lookup(
        &mut self,
        name: &'static str,
        is_write: Expression<F>,
        tag: RwTableTag,
        values: RwValues<F>,
    ) {
        self.rw_lookup_with_counter(
            name,
            self.curr.state.rw_counter.expr() + self.rw_counter_offset.clone(),
            is_write,
            tag,
            values,
        );
        // Manually constant folding is used here, since halo2 cannot do this
        // automatically. Better error message will be printed during circuit
        // debugging.
        self.rw_counter_offset = match &self.condition {
            None => {
                if let Constant(v) = self.rw_counter_offset {
                    Constant(v + F::from(1u64))
                } else {
                    self.rw_counter_offset.clone() + 1i32.expr()
                }
            }
            Some(c) => self.rw_counter_offset.clone() + c.clone(),
        };
    }

    // Stack

    pub(crate) fn stack_pop(&mut self, value: Expression<F>) {
        self.stack_lookup(false.expr(), self.stack_pointer_offset.clone(), value);
        self.stack_pointer_offset = self.stack_pointer_offset.clone() + self.condition_expr();
    }

    pub(crate) fn stack_push(&mut self, value: Expression<F>) {
        self.stack_pointer_offset = self.stack_pointer_offset.clone() - self.condition_expr();
        self.stack_lookup(true.expr(), self.stack_pointer_offset.expr(), value);
    }

    pub(crate) fn stack_lookup(
        &mut self,
        is_write: Expression<F>,
        stack_pointer_offset: Expression<F>,
        value: Expression<F>,
    ) {
        self.rw_lookup(
            "Stack lookup",
            is_write,
            RwTableTag::Stack,
            RwValues::new(
                self.curr.state.call_id.expr(),
                self.curr.state.stack_pointer.expr() + stack_pointer_offset,
                0.expr(),
                0.expr(),
                value,
                0.expr(),
                0.expr(),
                0.expr(),
            ),
        );
    }

    // Memory

    pub(crate) fn memory_lookup(
        &mut self,
        is_write: Expression<F>,
        memory_address: Expression<F>,
        byte: Expression<F>,
        call_id: Option<Expression<F>>,
    ) {
        self.rw_lookup(
            "Memory lookup",
            is_write,
            RwTableTag::Memory,
            RwValues::new(
                call_id.unwrap_or_else(|| self.curr.state.call_id.expr()),
                memory_address,
                0.expr(),
                0.expr(),
                byte,
                0.expr(),
                0.expr(),
                0.expr(),
            ),
        );
    }

    // General

    pub(crate) fn condition<R>(
        &mut self,
        condition: Expression<F>,
        constraint: impl FnOnce(&mut Self) -> R,
    ) -> R {
        debug_assert!(
            self.condition.is_none(),
            "Nested condition is not supported"
        );
        self.condition = Some(condition);
        let ret = constraint(self);
        self.condition = None;
        ret
    }

    /// This function needs to be used with extra precaution. You need to make
    /// sure the layout is the same as the gadget for `next_step_state`.
    /// `query_cell` will return cells in the next step in the `constraint`
    /// function.
    pub(crate) fn constrain_next_step<R>(
        &mut self,
        next_step_state: Opcode,
        condition: Option<Expression<F>>,
        constraint: impl FnOnce(&mut Self) -> R,
    ) -> R {
        assert!(!self.in_next_step, "Already in the next step");
        self.in_next_step = true;
        let ret = match condition {
            None => {
                self.require_next_state(next_step_state);
                constraint(self)
            }
            Some(cond) => self.condition(cond, |cb| {
                cb.require_next_state(next_step_state);
                constraint(cb)
            }),
        };
        self.in_next_step = false;
        ret
    }
    */
    pub(crate) fn add_constraints(&mut self, constraints: Vec<(&'static str, Expression<F>)>) {
        for (name, constraint) in constraints {
            self.add_constraint(name, constraint);
        }
    }

    pub(crate) fn add_constraint(&mut self, name: &'static str, constraint: Expression<F>) {
        /*
        let constraint = self.split_expression(
            name,
            constraint * self.condition_expr(),
            MAX_DEGREE - IMPLICIT_DEGREE,
        );
        */
        self.push_constraint(name, constraint);
    }

    /// TODO: Doc
    fn push_constraint(&mut self, name: &'static str, constraint: Expression<F>) {
        self.constraints.push((name, constraint));
    }
    /*
    pub(crate) fn add_lookup(&mut self, name: &str, lookup: Lookup<F>) {
        let lookup = match &self.condition {
            Some(condition) => lookup.conditional(condition.clone()),
            None => lookup,
        };

        let compressed_expr = self.split_expression(
            "Lookup compression",
            rlc::expr(&lookup.input_exprs(), self.power_of_randomness),
            MAX_DEGREE - IMPLICIT_DEGREE,
        );
        self.store_expression(name, compressed_expr, CellType::Lookup(lookup.table()));
    }

    fn condition_expr(&self) -> Expression<F> {
        match &self.condition {
            Some(condition) => condition.clone(),
            None => 1.expr(),
        }
    }
    */
}
