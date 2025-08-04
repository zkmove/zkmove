pub mod common {
    pub fn common_constraints() {
        /// common constraints
        constraint_clk();
        table_bytecode.lookup(
            module_index(0),
            function_index(0),
            pc(0),
            opcode(0),
            aux0(0),
            aux1(0),
        );
        if !on_last_row() {
            step_counter(1) == step_counter(0) - 1;
            module_index(1) == module_index(0);
            function_index(1) == function_index(0);
            frame_index(1) == frame_index(0);
            pc(1) == pc(0);
            opcode(1) == opcode(0);
            aux1(1) == aux1(0);
            aux2(1) == aux2(0);
        } else {
            step_counter(0) == 1;
        }
        stack_pop_version(0) < clk(0);
        local_read_version(0) < clk(0);
    }
    pub fn require_no_local_op() {
        local_read_version(0) == 0;
        local_write_version(0) == 0;
    }
    pub fn require_no_stack_pop() {
        stack_pop_version(0) == 0;
    }
    pub fn require_no_stack_push() {
        stack_push_version == 0;
    }
    pub fn constraint_clk() {
        // clk(0) == clk(-1) | clk(0) + 2 == clk(1)
        (clk(0) - clk(1)) * (clk(0) + 2 - clk(1))
    }
    pub fn on_first_row() {
        clk(0) - clk(-1)
    }
    pub fn on_last_row() {
        clk(1) - clk(0)
    }
    /// common constraints for move a filed under a reference
    /// example: ref_sub_index = [0,0,0,0,0,0,3,2], field_sub_index = [0,0,0,0,0,0,0,4], depth = 2
    /// reslult = [0,0,0,0,0,4,3,2]
    pub fn constrain_sub_index() {
        declare!(ref_sub_index, field_sub_index, depth, result);
        result == ref_sub_index + field_sub_index << (depth * 16);
        result <= MAX_U128;
    }
    pub fn constrain_depth() {
        declare!(ref_sub_index, depth);
        depth < 8;
        ref_sub_index >> (depth * 16) == 0;
        ref_sub_index >> ((depth - 1) * 16) != 0;
    }
}

mod call_stack {
    pub fn push() {
        let index = frame_index(0);
        let caller_module_index = module_index(0);
        let caller_function_index = function_index(0);
        let caller_pc = pc(0);
        let version = clk(0);
        callstack_push((
            index,
            caller_module_index,
            caller_function_index,
            caller_pc,
            version,
        ));
    }

    pub fn pop() {
        let (index, caller_module_index, caller_function_index, caller_pc, version) =
            callstack_pop();
        frame_index(1) == index;
        module_index(1) == caller_module_index;
        function_index(1) == caller_function_index;
        pc(1) == caller_pc + 1;
        version < clk(0);
    }
}

mod ld {
    fn constraint_ld() {
        step_counter(0) == 1;
        stack_push_index(0) == sp(0) + 1;
        stack_push_sub_index(0) == 0;
        stack_push_value(0) == [aux0(0), aux1(0)];
        stack_push_value_header(0) == false;
        stack_push_version(0) == clk(0);

        super::common::require_no_stack_pop();
        super::common::require_no_local_op();

        sp(1) == sp(0) + 1;
        module_index(1) == module_index(0);
        function_index(1) == function_index(0);
        frame_index(1) == frame_index(0);
        pc(1) == pc(0) + 1;
    }
}

mod ld_const {
    fn constraint() {
        if super::common::on_first_row() {
            if stack_push_value_header(0) {
                step_counter(0) == stack_push_value(0).as_header().f_len;
            } else {
                step_counter(0) == 1;
            }
            stack_push_sub_index(0) == 0;
        }
        table_constant.contain(
            module_index(0),
            aux0(0),
            stack_push_sub_index(0),
            stack_push_value(0),
            stack_push_value_header(0),
        );
        stack_push_index(0) == sp(0) + 1;
        stack_push_version(0) == clk(0);

        super::common::require_no_stack_pop();
        super::common::require_no_local_op();

        if super::common::on_last_row() {
            module_index(1) == module_index(0);
            function_index(1) == function_index(0);
            frame_index(1) == frame_index(0);
            pc(1) == pc(0) + 1;
            sp(1) == sp(0) + 1;
        }
    }
}

mod pop {
    fn constraint_pop() {
        let is_first = super::common::on_first_row();
        let is_last = super::common::on_last_row();

        if is_first {
            // if is complex value
            if stack_pop_value_header {
                // !simple value
                let flen = stack_pop_value(0).as_header().flen;
                step_counter(0) == flen;
            } else {
                step_counter(0) == 1;
            }
        }
        stack_pop_index(0) = sp(0);
        if is_first {
            stack_pop_sub_index(0) == 0;
        }
        // stack_pop_version(0) < clk(0);
        super::common::require_no_stack_push();
        super::common::require_no_local_op();

        if is_last {
            frame_index(1) == frame_index(0);
            module_index(1) == module_index(0);
            function_index(1) == function_index(0);
            sp(1) == sp(0) - 1;
            pc(1) = pc(0) + 1;
        }
    }
}

/// Common constraints for Add, Sub, Mul, Div, Mod, Shl, Shr
mod binary_op {
    pub fn constrain() {
        if super::common::on_first_row() {
            step_counter(0) == 2;
            super::common::require_no_stack_push();
            stack_pop_index(0) == sp(0);
            sp(1) == sp(0); //keep sp unchanged to make assign easier
        }

        stack_pop_sub_index(0) == 0;
        stack_pop_value_header(0) == false;
        // stack_pop_version(0) < clk(0);
        super::common::require_no_local_op();

        if super::common::on_last_row() {
            stack_pop_index(0) == sp(0) - 1;
            stack_push_index(0) == sp(0) - 1;
            stack_push_sub_index(0) == 0;

            let rhs = stack_pop_value(-1);
            let lhs = stack_pop_value(0);
            let out = binary_op(lhs, rhs);

            stack_push_value(0) == out;
            stack_push_value_header(0) == false;
            stack_push_version(0) == clk(0);

            module_index(1) == module_index(0);
            function_index(1) == function_index(0);
            frame_index(1) == frame_index(0);
            pc(1) == pc(0) + 1;
            sp(1) == sp(0) - 1;
        }
    }
}

mod bitwise {
    pub fn constrain() {
        if super::common::on_first_row() {
            step_counter(0) == 3;
        }

        if !super::common::on_last_row() {
            stack_pop_index(0) == sp(0) + step_counter(0) - 3;
            stack_pop_sub_index(0) == 0;
            stack_pop_value_header(0) == false;
            // stack_pop_version(0) < clk(0);
            super::common::require_no_stack_push();
            sp(1) == sp(0); //keep sp unchanged to make assign easier
        }

        super::common::require_no_local_op();

        if super::common::on_last_row() {
            super::common::require_no_stack_pop();
            stack_push_index(0) == sp(0) - 1;
            stack_push_sub_index(0) == 0;
            bitwise_table.lookup(
                opcode(0),
                stack_pop_value(-1),
                stack_pop_value(-2),
                stack_push_value(0),
            );
            stack_push_value_header(0) == false;
            stack_push_version(0) == clk(0);

            module_index(1) == module_index(0);
            function_index(1) == function_index(0);
            frame_index(1) == frame_index(0);
            pc(1) == pc(0) + 1;
            sp(1) == sp(0) - 1;
        }
    }
}

mod le {
    fn constraint_le(is_le: bool) {
        let is_first = super::common::on_first_row();
        let is_last = super::common::on_last_row();

        if is_first {
            if is_le {
                opcode(0) == OpCode::Le;
            } else {
                opcode(0) == OpCode::Gt;
            }
            step_counter(0) == 2;
            super::common::require_no_stack_push();
            stack_pop_index(0) == sp(0);
            sp(1) == sp(0); //keep sp unchanged to make assign easier
        }
        stack_pop_sub_index(0) == 0;
        stack_pop_value_header(0) == false;
        // stack_pop_version(0) < clk(0);
        super::common::require_no_local_op();

        if is_last {
            stack_pop_index(0) == sp(0) - 1;
            stack_push_index(0) == sp(0) - 1;
            stack_push_sub_index(0) == 0;
            let out = if is_le {
                stack_pop_value(0) <= stack_pop_value(-1)
            } else {
                stack_pop_value(0) > stack_pop_value(-1)
            };
            stack_push_value(0) == out;
            stack_push_value_header(0) == false;
            stack_push_version(0) == clk(0);

            module_index(1) == module_index(0);
            function_index(1) == function_index(0);
            frame_index(1) == frame_index(0);
            pc(1) == pc(0) + 1;
            sp(1) == sp(0) - 1;
        }
    }
}

mod lt {
    fn constraint_le(is_le: bool) {
        let is_first = super::common::on_first_row();
        let is_last = super::common::on_last_row();

        if is_first {
            if is_lt {
                opcode(0) == OpCode::Lt;
            } else {
                opcode(0) == OpCode::Ge;
            }
            step_counter(0) == 2;
            super::common::require_no_stack_push();
            stack_pop_index(0) == sp(0);
            sp(1) == sp(0); //keep sp unchanged to make assign easier
        }
        stack_pop_sub_index(0) == 0;
        stack_pop_value_header(0) == false;
        // stack_pop_version(0) < clk(0);
        super::common::require_no_local_op();

        if is_last {
            stack_pop_index(0) == sp(0) - 1;
            stack_push_index(0) == sp(0) - 1;
            stack_push_sub_index(0) == 0;
            let out = if is_lt {
                stack_pop_value(0) < stack_pop_value(-1)
            } else {
                stack_pop_value(0) >= stack_pop_value(-1)
            };
            stack_push_value(0) == out;
            stack_push_value_header(0) == false;
            stack_push_version(0) == clk(0);

            module_index(1) == module_index(0);
            function_index(1) == function_index(0);
            frame_index(1) == frame_index(0);
            pc(1) == pc(0) + 1;
            sp(1) == sp(0) - 1;
        }
    }
}

// TODO: Reference type value comparison, actually it can convert to (pop,pop,read_ref,read_ref,stage1...)
mod eq {
    pub fn constrain_eq_stage_1_or_2(is_stage_1: bool) {
        let stack_pop_rlc = stack_pop_sub_index(0) + gamma * stack_pop_value_header(0) + gamma
            ^ 2 * stack_pop_value(0);

        if super::common::on_first_row() {
            if !is_stage_1 {
                execution_state_prev == EqStage1;
            }
            opcode(0) == OpCode::EQ;
            stack_pop_sub_index(0) == 0;

            if stack_pop_value_header(0) {
                step_counter(0) == stack_pop_value(0).as_header().flen;
            } else {
                step_counter(0) == 1;
            }
            stack_pop_sub_index_reverse(0) == 0;

            if is_stage_1 {
                rlc1(0) == stack_pop_rlc;
            } else {
                rlc2(0) == stack_pop_rlc;
            }
        }

        if !super::common::on_first_row() {
            // define stack_pop_sub_index_reverse to constrain sub_index monotonically increasing.
            // prevents malicious prover from faking eq as neq by comparing different sub_index.
            stack_pop_sub_index_reverse(0) == SubIndexReverse::expr(stack_pop_sub_index(0));
            stack_pop_sub_index_reverse(0) > stack_pop_sub_index_reverse(-1);

            if is_stage_1 {
                //in order not to conflict with inner rlc, we use gamma^4 as randomness
                rlc1(0) == gamma ^ 4 * rlc1(-1) + stack_pop_rlc;
            } else {
                rlc2(0) == gamma ^ 4 * rlc2(-1) + stack_pop_rlc;
            }
        }

        stack_pop_index(0) == sp(0);
        // stack_pop_version(0) < clk(0);
        super::common::require_no_local_op();
        if !is_stage_1 {
            rlc1(0) == rlc1(-1);
        }

        if !super::common::on_last_row() {
            sp(1) == sp(0);
            super::common::require_no_stack_push();
        }

        if super::common::on_last_row() {
            if is_stage_1 {
                super::common::require_no_stack_push();
                module_index(1) == module_index(0);
                function_index(1) == function_index(0);
                frame_index(1) == frame_index(0);
                sp(1) == sp(0) - 1;
                pc(1) == pc(0);
                execution_state_next == EqStage2;
            } else {
                stack_push_index(0) == sp(0);
                stack_push_sub_index(0) == 0;
                stack_push_value(0) == true | false;
                stack_push_value_header(0) == false;
                stack_push_version(0) == clk(0);

                if stack_push_value(0) {
                    rlc1(0) == rlc2(0);
                } else {
                    rlc1(0) != rlc2(0);
                }

                module_index(1) == module_index(0);
                function_index(1) == function_index(0);
                frame_index(1) == frame_index(0);
                sp(1) == sp(0);
                pc(1) == pc(0) + 1;
            }
        }
    }
}

mod not {
    pub fn constrain() {
        opcode(0) == OpCode::Not;
        step_counter(0) == 1;

        stack_pop_index(0) == sp(0);
        stack_pop_sub_index(0) == 0;
        stack_pop_value(0) == 0 | 1;
        stack_pop_value_header(0) == false;
        // stack_pop_version(0) < clk(0);
        stack_push_index(0) == sp(0);
        stack_push_sub_index(0) == 0;
        stack_push_value(0) == !stack_pop_value(0);
        stack_push_value_header(0) == false;
        stack_push_version(0) == clk(0);

        super::common::require_no_local_op();

        module_index(1) == module_index(0);
        function_index(1) == function_index(0);
        frame_index(1) == frame_index(0);
        pc(1) == pc(0) + 1;
        sp(1) == sp(0);
    }
}

mod and_or {
    pub fn constrain() {
        if super::common::on_first_row() {
            aux(0) == 0 | 1;
            if aux(0) {
                opcode(0) == OpCode::And;
            } else {
                opcode(0) == OpCode::Not;
            }
            step_counter(0) == 2;
            super::common::require_no_stack_push();
            stack_pop_index(0) == sp(0);
            sp(1) == sp(0); //keep sp unchanged to make assign easier
        }

        stack_pop_sub_index(0) == 0;
        stack_pop_value(0) == 0 | 1;
        stack_pop_value_header(0) == false;
        // stack_pop_version(0) < clk(0);
        super::common::require_no_local_op();

        if super::common::on_last_row() {
            stack_pop_index(0) == sp(0) - 1;
            stack_push_index(0) == sp(0) - 1;
            stack_push_sub_index(0) == 0;
            let expected = if aux(0) {
                stack_pop_value(-1) && stack_pop_value(0)
            } else {
                stack_pop_value(-1) || stack_pop_value(0)
            };
            stack_push_value(0) == expected;
            stack_push_value_header(0) == false;
            stack_push_version(0) == clk(0);

            module_index(1) == module_index(0);
            function_index(1) == function_index(0);
            frame_index(1) == frame_index(0);
            pc(1) == pc(0) + 1;
            sp(1) == sp(0) - 1;
        }
    }
}

mod cast {
    pub fn constrain_cast() {
        step_counter(0) == 1;

        stack_pop_index(0) == sp(0);
        stack_pop_sub_index(0) == 0;
        stack_pop_value_header(0) == false;
        // stack_pop_version(0) < clk(0);
        stack_push_index(0) == sp(0);
        stack_push_sub_index(0) == 0;
        stack_push_value_header(0) == false;
        stack_push_version(0) == clk(0);

        super::common::require_no_local_op();

        let ok = range_check(stack_pop_value(0));
        if ok {
            stack_push_value(0) == stack_pop_value(0);
            module_index(1) == module_index(0);
            function_index(1) == function_index(0);
            frame_index(1) == frame_index(0);
            pc(1) == pc(0) + 1;
            sp(1) == sp(0);
        } else {
            execution_state_next == ErrorState;
            ErrorCode == StatusCode::ArithmeticError;
        }
    }
}

mod ret {
    pub fn constrain() {
        opcode(0) == OpCode::Ret;
        step_counter(0) == 1;

        super::common::require_no_stack_pop();
        super::common::require_no_stack_push();
        super::common::require_no_local_op();

        // constrain Opcode Context of the next step
        if frame_index == 0 {
            execution_state_next == STOP | Teardown;
        } else {
            // not the first frame
            super::call_stack::pop();
            frame_index(1) == frame_index(0) - 1;
            sp(1) == sp(0);
        }
    }
}

mod call {
    /// check the number of argument. If the function has no arguments, enter callee, else enter stage2
    pub fn constrain_call_stage_1() {
        opcode(0) == OpCode::Call;
        step_counter(0) == 1;

        super::common::require_no_stack_pop();
        super::common::require_no_stack_push();
        super::common::require_no_local_op();

        sp(1) == sp(0);
        if num_arg(0) == 0 {
            table_func.contain(
                module_index(0),
                aux0(0), //fh_idx
                module_index(1),
                function_index(1),
                num_arg(0),
            );
            pc(1) == 0;
            frame_index(1) == frame_index(0) + 1;
            super::call_stack::push();
        } else {
            execution_state_next == call_stage_2;
            num_arg(1) == num_arg(0);
            local_index(1) == num_arg(0) - 1;

            module_index(1) == module_index(0);
            function_index(1) == function_index(0);
            frame_index(1) == frame_index(0);
            pc(1) == pc(0);
            opcode(1) == opcode(0);
            aux0(1) == aux0(0);
            aux1(1) == aux1(0);
        }
    }

    /// invalidate old value in the local_index corresponding to an argument.
    /// the next stage must be stage3. we need to enter this stage 'num_arg' times.
    pub fn constrain_call_stage_2() {
        if super::common::on_first_row() {
            execution_state_prev == call_stage_1 | call_stage_3;
            local_sub_index(0) == 0;

            if !local_read_value_invalid(0) && local_read_value_header(0) {
                step_counter(0) == local_read_value(0).as_header().flen;
            } else {
                step_counter(0) == 1;
            }
        }

        super::common::require_no_stack_pop();
        super::common::require_no_stack_push();

        local_frame_index(0) == frame_index(0) + 1; // write to local of the next frame
                                                    // local_index(0) is constrained in the last row
                                                    // actually we don't care about old local is invalid or not.
                                                    // local_read_version(0) < clk(0);
        local_write_value_invalid(0) == true;
        local_write_value(0) == local_read_value(0);
        local_write_value_header(0) == local_read_value_header(0);
        local_write_version(0) == clk(0);

        sp(1) == sp(0);
        local_index(1) == local_index(0);
        num_arg(1) == num_arg(0);

        if super::common::on_last_row() {
            execution_state_next == call_stage_3;
            frame_index(1) == frame_index(0);
            module_index(1) == module_index(0);
            function_index(1) == function_index(0);
            pc(1) == pc(0);
            opcode(1) == opcode(0);
            aux0(1) == aux0(0);
            aux1(1) == aux1(0);
        }
    }

    /// pop an argument and store into local of the next frame.
    /// the previous stage must be stage2. The next stage is still stage2, unless we have
    /// processed all the arguments. We need to enter this stage 'num_arg' times.
    pub fn constrain_call_stage_3() {
        if super::common::on_first_row() {
            execution_state_prev == call_stage_2;

            stack_pop_sub_index(0) == 0;
            if stack_pop_value_header(0) {
                step_counter(0) == stack_pop_value(0).as_header().flen;
            } else {
                step_counter(0) == 1;
            }
        }

        stack_pop_index(0) == sp(0);
        // stack_pop_version(0) < clk(0);

        local_frame_index(0) == frame_index(0) + 1; //write to local of next frame
        local_sub_index(0) == stack_pop_sub_index(0);
        local_read_value_invalid == 1;
        // local_read_version(0) < clk(0);
        local_write_value(0) == stack_pop_value(0);
        local_write_value_header(0) == stack_pop_value_header(0);
        local_write_value_invalid == 0;
        local_write_version(0) == clk(0);
        super::common::require_no_stack_push();

        if !super::common::on_last_row() {
            sp(1) == sp(0);
            local_index(1) == local_index(0);
            num_arg(1) == num_arg(0);
        }
        if super::common::on_last_row() {
            sp(1) == sp(0) - 1;
            if local_index == 0 {
                //all args have been processed
                table_func.contain(
                    module_index(0),
                    aux0(0), //fh_index
                    module_index(1),
                    function_index(1),
                    num_arg(0),
                );
                frame_index(1) == frame_index(0) + 1;
                pc(1) == 0;
                super::call_stack::push();
            } else {
                execution_state_next == call_stage_2;
                local_index(1) == local_index(0) - 1;
                module_index(1) == module_index(0);
                function_index(1) == function_index(0);
                frame_index(1) == frame_index(0);
                pc(1) == pc(0);
                opcode(1) == opcode(0);
                aux0(1) == aux0(0);
                aux1(1) == aux1(0);
            }
        }
    }
}

mod move_loc {
    fn constraint() {
        let is_first = super::common::on_first_row();
        let is_last = super::common::on_last_row();

        if is_first {
            // first row
            local_sub_index(0) == 0; // simple value or header
            if stack_push_value_header {
                // !simple value
                let flen = stack_push_value(0).as_header().flen;
                step_counter(0) == flen; // need to constraint flen == step_counter in the first row.
            } else {
                step_counter(0) == 1;
            }
        }

        stack_push_index(0) == sp(0) + 1; // push a value onto stack
        stack_push_version(0) == clk(0);
        local_frame_index(0) == frame_index(0);
        local_index(0) == aux0(0); // ensure local_index equal to operand0
        local_sub_index(0) == stack_push_sub_index(0);
        local_read_value(0) == stack_push_value(0);
        local_read_value_header(0) == stack_push_value_header(0);
        lcoal_read_value(0) != INVALID;
        local_write_value(0) == INVALID; // move_loc will invalidate origin local slot.
                                         // constraint local-invalidating has the same write_version
        local_write_version(0) == clk(0);
        // local_write_version(0) > local_read_version(0);
        super::common::require_no_stack_pop();

        if is_last {
            frame_index(1) == frame_index(0);
            module_index(1) == module_index(0);
            function_index(1) == function_index(0);
            pc(1) == pc(0) + 1;
            sp(1) == sp(0) + 1;
        }
    }
}

mod copy_loc {
    fn constraint() {
        let is_first = super::common::on_first_row();
        let is_last = super::common::on_last_row();

        if is_first {
            // first row
            local_sub_index(0) == 0; // simple value or header
            if stack_push_value_header {
                // !simple value
                let flen = stack_push_value(0).as_header().flen;
                step_counter(0) == flen; // need to constraint flen == step_counter in the first row.
            } else {
                step_counter(0) == 1;
            }
        }

        stack_push_index(0) == sp(0) + 1; // push a value onto stack
        stack_push_version(0) == clk(0);
        local_frame_index(0) == frame_index(0);
        local_index(0) == aux0(0); // ensure local_index equal to operand0
        local_sub_index(0) == stack_push_sub_index(0);
        lcoal_read_value(0) != INVALID;
        local_read_value(0) == stack_push_value(0);
        local_read_value_header(0) == stack_push_value_header(0);
        local_write_value(0) == local_read_value(0); // copy_loc will just read data, this the only difference with move_loc
        local_write_value_header(0) == local_read_value_header(0);
        local_write_value_invalid(0) == local_read_value_invalid(0);
        // constraint local-invalidating has the same write_version
        local_write_version(0) == clk(0);
        // local_write_version(0) > local_read_version(0);
        super::common::require_no_stack_pop();

        if is_last {
            frame_index(1) == frame_index(0);
            module_index(1) == module_index(0);
            function_index(1) == function_index(0);
            pc(1) == pc(0) + 1;
            sp(1) == sp(0) + 1;
        }
    }
}

/// store_loc have two stages.
/// 1. first, we invalidate the local slot to store. If the local is empty, it should read as invalid, and write back the invalid, increasing the version.
/// 2. then, we move the value on stack to loc.
mod store_loc {
    fn stage1() {
        let is_first = super::common::on_first_row();
        let is_last = super::common::on_last_row();
        if is_first {
            if local_read_value_header(0) {
                // !simple value
                let flen = local_read_value(0).as_header().flen;
                step_counter(0) == flen; // need to constraint flen == step_counter in the first row.
            } else {
                step_counter(0) == 1;
            }
        }
        local_frame_index(0) == frame_index(0);
        // ensure local_index equal to operand0
        local_index(0) == aux0(0);
        if is_first {
            // first row
            local_sub_index(0) == 0; // simple value or header
        }
        // we don't care local is invalid or not.
        // local_read_value_invalid,local_read_value_header, local_read_value, local_read_version.
        // local_read_version(0) < clk(0);
        local_write_value_invalid(0) == true;
        local_write_value_header(0) == local_read_value_header(0);
        local_write_version(0) == clk(0);
        super::common::require_no_stack_pop();
        super::common::require_no_stack_push();
        sp(1) == sp(0);
        if is_last {
            frame_index(1) == frame_index(0);
            module_index(1) == module_index(0);
            function_index(1) == function_index(0);
            pc(1) == pc(0);
            opcode(1) == opcode(0);
            aux0(1) == aux0(0);
            aux1(1) == aux1(0);
        }
    }

    // move value from stack to local
    fn stage2() {
        let is_first = super::common::on_first_row();
        let is_last = super::common::on_last_row();

        stack_pop_index(0) == sp(0);
        if is_first {
            // first row
            stack_pop_sub_index(0) == 0; // simple value or header
        }
        if is_first {
            if stack_pop_value_header {
                // !simple value
                let flen = stack_pop_value(0).as_header().flen;
                step_counter(0) == flen; // need to constraint flen == step_counter in the first row.
            } else {
                step_counter(0) == 1;
            }
        }
        // stack_pop_version(0) < clk(0);
        super::common::require_no_stack_push();

        local_frame_index(0) == frame_index(0);
        local_index(0) == aux0(0);
        local_sub_index(0) == stack_pop_sub_index(0);

        local_read_value_invalid(0) == true;
        // local_read_version(0) < clk(0);
        local_write_value(0) == stack_pop_value(0);
        local_write_value_header(0) == stack_pop_value_header(0);
        local_write_value_invalid(0) == false;
        local_write_version(0) == clk(0);
        if is_last {
            frame_index(1) == frame_index(0);
            module_index(1) == module_index(0);
            function_index(1) == function_index(0);
            pc(1) == pc(0) + 1;
            sp(1) == sp(0) - 1;
        } else {
            sp(1) == sp(0);
        }
    }
}

mod borrow_loc {
    pub fn constrain() {
        step_counter(0) == 1;
        let index = frame_index(0) + aux(0) << 16; //both frame_index and local_index are u16
        let sub_index = 0;
        stack_push_value(0) == [index, sub_index];
        stack_push_value_header(0) == false;
        stack_push_index(0) == sp(0) + 1;
        stack_push_sub_index(0) == 0;
        stack_push_version(0) == clk(0);

        super::common::require_no_stack_pop();
        super::common::require_no_local_op();

        module_index(1) == module_index(0);
        function_index(1) == function_index(0);
        frame_index(1) == frame_index(0);
        pc(1) == pc(0) + 1;
        sp(1) == sp(0) + 1;
    }
}

mod borrow_field {
    pub fn constrain() {
        step_counter(0) == 1;
        stack_pop_index(0) == sp(0);
        stack_pop_sub_index(0) == 0;
        // stack_pop_version(0) < clk(0);

        stack_push_value(0).as_reference().index == stack_pop_value(0).as_reference().index;
        stack_push_value(0).as_reference().sub_index
            == stack_pop_value(0)
                .as_reference()
                .sub_index
                .concat(aux0(0) + 1);
        stack_push_value_header(0) == stack_pop_value_header(0);
        stack_push_index(0) == sp(0);
        stack_push_sub_index(0) == 0;
        stack_push_version(0) == clk(0);

        super::common::require_no_local_op();

        module_index(1) == module_index(0);
        function_index(1) == function_index(0);
        frame_index(1) == frame_index(0);
        pc(1) == pc(0) + 1;
        sp(1) == sp(0);
    }
}

mod read_ref {
    pub fn constrain() {
        if super::common::on_first_row() {
            opcode(0) == OpCode::READ_REF;
            stack_pop_index(0) == sp(0);
            stack_pop_sub_index(0) == 0;
            // stack_pop_version(0) < clk(0);
            (local_frame_index(0), local_index(0)) == stack_pop_value(0).as_reference().index;
            local_sub_index(0) == stack_pop_value(0).as_reference().sub_index;

            if local_read_value_header(0) {
                step_counter(0) == local_read_value(0).as_header().f_len;
            } else {
                step_counter(0) == 1;
            }
            // record the sub index of the referenced value's header
            header_sub_index(0) == local_sub_index(0);
        }
        if !super::common::on_first_row() {
            super::common::require_no_stack_pop();
        }

        stack_push_index(0) == sp(0);
        local_sub_index(0) == header_sub_index(0).concat(stack_push_sub_index(0));
        stack_push_value(0) == local_read_value(0);
        stack_push_value_header(0) == local_read_value_header(0);
        stack_push_version(0) == clk(0);
        // local_read_version(0) < clk(0);
        local_write_value(0) == local_read_value(0);
        local_write_value_header(0) == local_read_value_header(0);
        local_write_value_invalid(0) == local_read_value_invalid(0);
        local_write_version(0) == clk(0);

        sp(1) == sp(0);
        if !super::common::on_last_row() {
            // non-last step
            local_frame_index(1) == local_frame_index(0);
            local_index(1) == local_index(0);
            header_sub_index(1) == header_sub_index(0);
        }
        if super::common::on_last_row() {
            module_index(1) == module_index(0);
            function_index(1) == function_index(0);
            frame_index(1) == frame_index(0);
            pc(1) == pc(0) + 1;
        }
    }
}

mod write_ref {
    //STAGE_POP_REF_AND_INVALIDATE_OLD
    pub fn constrain_write_ref_stage_1() {
        if super::common::on_first_row() {
            opcode(0) == OpCode::WriteRef;
            stack_pop_index(0) == sp(0);
            stack_pop_sub_index(0) == 0;
            // stack_pop_version(0) < clk(0);
            (local_frame_index(0), local_index(0)) == stack_pop_value(0).as_reference().index;
            local_sub_index(0) == stack_pop_value(0).as_reference().sub_index;

            if local_read_value_header(0) {
                step_counter(0) == local_read_value(0).as_header().f_len;
            } else {
                step_counter(0) == 1;
            }
            // record the sub index of the referenced value,
            // for updating parent header later
            header_sub_index(0) == local_sub_index(0);
            header_flen_delta(0) == step_counter(0);
        }

        if !super::common::on_first_row() {
            Membership::configure(header_sub_index(0), local_sub_index(0));
            super::common::require_no_stack_pop();
        }
        super::common::require_no_stack_push();

        // local_read_version(0) < clk(0);
        local_write_invalid_value();
        local_write_version(0) == clk(0);
        super::common::require_no_stack_push();
        // sp always the same, even for last row
        local_frame_index(1) == local_frame_index(0);
        local_index(1) == local_index(0);
        header_sub_index(1) == header_sub_index(0);

        if !super::common::on_last_row() {
            header_flen_delta(1) == header_flen_delta(0);
            sp(1) == sp(0);
        }

        if super::common::on_last_row() {
            module_index(1) == module_index(0);
            function_index(1) == function_index(0);
            frame_index(1) == frame_index(0);
            pc(1) == pc(0);
            sp(1) == sp(0) - 1;
            execution_state_next == WriteRefStage2;
        }
    }

    //STAGE_POP_NEW_VALUE_AND_WRITE
    pub fn constrain_write_ref_stage_2() {
        if super::common::on_first_row() {
            execution_state_prev == WriteRefStage1;
            if stack_pop_value_header(0) {
                step_counter(0) == stack_pop_value(0).as_header().f_len;
            } else {
                step_counter(0) == 1;
            }
            header_flen_delta(0) == step_counter(0) - header_flen_delta(-1);
            stack_pop_sub_index(0) == 0;
        }

        stack_pop_index(0) == sp(0);
        // stack_pop_version(0) < clk(0);
        local_sub_index(0) == header_sub_index(0).concat(stack_pop_sub_index(0));
        local_read_invalid_value();
        // local_read_version(0) < clk(0);
        local_write_value(0) == stack_pop_value(0);
        local_write_value_header(0) == stack_pop_value_header(0);
        local_write_version(0) == clk(0);
        super::common::require_no_stack_push();

        if !super::common::on_last_row() {
            header_sub_index(1) == header_sub_index(0);
            header_flen_delta(1) == header_flen_delta(0);
            local_frame_index(1) == local_frame_index(0);
            local_index(1) == local_index(0);
            sp(1) == sp(0);
        }

        if super::common::on_last_row() {
            module_index(1) == module_index(0);
            function_index(1) == function_index(0);
            frame_index(1) == frame_index(0);
            sp(1) == sp(0) - 1;

            if header_sub_index(0) != 0 {
                pc(1) == pc(0);
                execution_state_next == WriteRefStage3;
            } else {
                // don't need update parent
                pc(1) == pc(0) + 1;
            }
        }
    }

    //STAGE_UPDATE_PARENT from bottom up
    pub fn constrain_write_ref_stage_3() {
        if super::common::on_first_row() {
            execution_state_prev == WriteRefStage2;
            // remove this, it's not necessary. we will stop when header_sub_index = 0
            // step_counter(0) == header_sub_index(-1).depth();
            header_flen_delta(0) == header_flen_delta(-1);
            local_frame_index(0) == local_frame_index(-1);
            local_index(0) == local_index(-1);
        }
        super::common::require_no_stack_pop();
        super::common::require_no_stack_push();

        header_sub_index(0) == header_sub_index(-1).parent;
        header_sub_index(0) != header_sub_index(-1);
        // local_read_version(0) < clk(0);
        local_sub_index(0) == header_sub_index(0);
        local_write_value(0).as_header().flen
            == local_read_value(0).as_header().flen + header_flen_delta(0);
        local_write_value_header(0) == local_read_value_header(0);
        local_write_value_invalid(0) == local_read_value_invalid(0);
        local_write_version(0) == clk(0);
        // sp always the same, even for last row
        sp(1) == sp(0);

        if !super::common::on_last_row() {
            header_flen_delta(1) == header_flen_delta(0);
            local_frame_index(1) == local_frame_index(0);
            local_index(1) == local_index(0);
        }
        if super::common::on_last_row() {
            header_sub_index(0) = 0; // stop at the top parent
            module_index(1) == module_index(0);
            function_index(1) == function_index(0);
            frame_index(1) == frame_index(0);
            pc(1) == pc(0) + 1;
        }
    }
}

mod br_bool {
    pub fn constrain() {
        if on_first_row() {
            step_counter(0) == 1;
        }
        let next_pc = aux0(0);
        stack_pop_index(0) == sp(0);
        stack_pop_sub_index(0) == 0;
        // stack_pop_version(0) < clk(0);
        let cond = stack_pop_value(0);
        super::common::require_no_stack_push();
        super::common::require_no_local_op();

        if on_last_row() {
            // Memory Context Constraints:
            pc(1)
                == if opcode == BrTure {
                    cond * next_pc + (1 - cond) * (pc(0) + 1)
                } else {
                    (1 - cond) * next_pc + cond * (pc(0) + 1)
                };
            sp(1) == sp(0) - 1;
        }
    }
}

mod branch {
    pub fn constrain() {
        table_bytecode.lookup(pc(0), opcode(0), aux0(0), aux1(0));

        super::common::require_no_stack_pop();
        super::common::require_no_stack_push();
        super::common::require_no_local_op();

        sp(1) == sp(0);
        pc(1) == aux0(0);
    }
}

mod pack {
    pub fn constrain(is_vec_pack: bool) {
        let num_field = aux0(0);
        if super::common::on_first_row() {
            if is_vec_pack {
                opcode(0) == OpCode::VecPack;
            } else {
                opcode(0) == OpCode::Pack;
            }
            stack_push_index(0) == sp(0) - num_field + 1;
            stack_push_sub_index(0) == 0;
            stack_push_value(0).as_header().len() == num_field;
            stack_push_value(0).as_header().flen() == step_counter(0);
            stack_push_value_header(0) == true;
            stack_push_version(0) == clk(0);

            super::common::require_no_stack_pop();
            super::common::require_no_local_op();

            if num_field != 0 {
                field_index(1) == aux0(0);
                stack_pop_index(1) == sp(0);
                stack_pop_sub_index(1) == 0;
            }
            if num_field == 0 {
                //empty vec
                step_counter(0) == 1;
            }
        }

        if !super::common::on_first_row() {
            if stack_pop_sub_index(0) == 0 {
                if !stack_pop_value_header(0) {
                    field_counter(0) == 1;
                }
                if stack_pop_value_header(0) {
                    field_counter(0) == stack_pop_value(0).as_header().flen;
                }
            }

            // stack_pop_version(0) < clk(0);
            stack_push_index(0) == sp(0) - num_field + 1;
            stack_push_sub_index(0)
                == stack_pop_sub_index(0) * DEPTH_POW_OF_ONE_LEVEL + field_index(0);
            stack_push_value(0) == stack_pop_value(0);
            stack_push_value_header(0) == stack_pop_value_header(0);
            stack_push_version(0) == clk(0);
            super::common::require_no_local_op();

            if !super::common::on_last_row() {
                let end_of_one_field = field_counter(0) == 1;
                if end_of_one_field {
                    field_index(1) == field_index(0) - 1;
                    stack_pop_index(1) == stack_pop_index(0) - 1;
                    stack_pop_sub_index(1) == 0;
                } else {
                    field_index(1) == field_index(0);
                    field_counter(1) == field_counter(0) - 1;
                    stack_pop_index(1) == stack_pop_index(0);
                }
            }
        }

        if !super::common::on_last_row() {
            sp(1) == sp(0);
        }

        if super::common::on_last_row() {
            if num_field != 0 {
                // all fields processed
                field_index(0) == 1;
                field_counter(0) == 1;
            }
            sp(1) == sp(0) - num_field + 1;
            module_index(1) == module_index(0);
            function_index(1) == function_index(0);
            frame_index(1) == frame_index(0);
            pc(1) == pc(0) + 1;
        }
    }
}

mod unpack {
    /// pop vector header
    pub fn constrain_stage_1(is_vec_unpack: bool) {
        if super::common::on_first_row() {
            if is_vec_unpack {
                opcode(0) == OpCode::VecUnpack;
            } else {
                opcode(0) == OpCode::Unpack;
            }
            step_counter(0) == 1;
            stack_pop_index(0) == sp(0);
            stack_pop_sub_index(0) == 0;
            stack_pop_value(0).as_header().len() == aux0(0);
            // stack_pop_version(0) < clk(0);

            super::common::require_no_stack_push();
            super::common::require_no_local_op();

            module_index(1) == module_index(0);
            function_index(1) == function_index(0);
            frame_index(1) == frame_index(0);
            if !is_vec_unpack {
                execution_state_next == UnpackStage2;
                pc(1) == pc(0);
                sp(1) == sp(0);
                field_index(1) == aux0(0);
            }
            // the difference between vec_unpack and unpack is that vec can be empty
            if is_vec_unpack {
                if aux0(0) != 0 {
                    execution_state_next == UnpackStage2;
                    pc(1) == pc(0);
                    sp(1) == sp(0);
                    field_index(1) == aux0(0);
                } else {
                    //num_field == 0
                    pc(1) == pc(0) + 1;
                    sp(1) == sp(0) - 1;
                }
            }
        }
    }

    /// pop one field and push to stack
    pub fn constrain_stage_2() {
        if super::common::on_first_row() {
            execution_state_prev == UnpackStage1 | UnpackStage2;
            stack_pop_sub_index(0) == field_index(0); // [field_index,0,0,0]
            if stack_pop_value_header(0) {
                step_counter(0) == stack_pop_value(0).as_header().flen;
            } else {
                step_counter(0) == 1;
            }
        }

        if !super::common::on_first_row() {
            // we can only pop the member of [field_index,0,0,0]
            Membership::configure(field_index(0), stack_pop_sub_index(0));
        }

        stack_pop_index(0) == sp(0);
        // stack_pop_version(0) < clk(0);
        stack_push_index(0) == sp(0) + field_index(0) - 1;
        stack_push_sub_index(0) * DEPTH_POW_OF_ONE_LEVEL + field_index(0) == stack_pop_sub_index(0);
        stack_push_value(0) == stack_pop_value(0);
        stack_push_value_header(0) == stack_pop_value_header(0);
        stack_push_version(0) == clk(0);
        super::common::require_no_local_op();

        if !super::common::on_last_row() {
            sp(1) == sp(0);
            field_index(1) == field_index(0);
        }

        if super::common::on_last_row() {
            if field_index(0) != 1 {
                execution_state_next == UnpackStage2;
                pc(1) == pc(0);
                sp(1) == sp(0);
                field_index(1) == field_index(0) - 1;
            }
            if field_index(0) == 1 {
                pc(1) == pc(0) + 1;
                sp(1) == sp(0) + aux0(0) - 1; // sp(0)+num_field-1
            }
            module_index(1) == module_index(0);
            function_index(1) == function_index(0);
            frame_index(1) == frame_index(0);
        }
    }
}

mod vec_len {
    pub fn constrain() {
        opcode(0) == OpCode::VecLen;
        step_counter(0) == 1;
        stack_pop_index(0) == sp(0);
        stack_pop_sub_index(0) == 0;
        // stack_pop_version(0) < clk(0);

        // read vec header
        (local_frame_index(0), local_index(0)) == stack_pop_value(0).as_reference().index;
        local_sub_index(0) == stack_pop_value(0).as_reference().sub_index;
        local_read_value_header(0) == true;
        local_read_value_invalid(0) == false;
        // local_read_version(0) < clk(0);
        local_write_value(0) == local_read_value(0);
        local_write_value_header(0) == local_read_value_header(0);
        local_write_value_invalid(0) == local_read_value_invalid(0);
        local_write_version(0) == clk(0);

        stack_push_index(0) == sp(0);
        stack_push_sub_index(0) == 0;
        stack_push_value(0).as_integer().lo == local_read_value(0).as_header().len;
        stack_push_value(0).as_integer().hi == 0;
        stack_push_value_header(0) == false;
        stack_push_version(0) == clk(0);

        module_index(1) == module_index(0);
        function_index(1) == function_index(0);
        frame_index(1) == frame_index(0);
        pc(1) == pc(0) + 1;
        sp(1) == sp(0);
    }
}

mod vec_borrow {
    pub fn constrain() {
        if super::common::on_first_row() {
            opcode(0) == OpCode::VecBorrow;
            step_counter(0) == 2;
            super::common::require_no_stack_push();
            stack_pop_index(0) == sp(0);
            sp(1) == sp(0);
        }

        stack_pop_sub_index(0) == 0;
        stack_pop_value_header(0) == false;
        // stack_pop_version(0) < clk(0);
        super::common::require_no_local_op();

        if super::common::on_last_row() {
            stack_pop_index(0) == sp(0) - 1;
            stack_push_index(0) == sp(0) - 1;
            stack_push_sub_index(0) == 0;
            stack_push_value(0).as_reference().index == stack_pop_value(0).as_reference().index;
            stack_push_value(0).as_reference().sub_index
                == stack_pop_value(0)
                    .as_reference()
                    .sub_index
                    .concat(stack_pop_value(-1).as_integer().lo() + 1);
            stack_push_value_header(0) == stack_pop_value_header(0);
            stack_push_version(0) == clk(0);

            module_index(1) == module_index(0);
            function_index(1) == function_index(0);
            frame_index(1) == frame_index(0);
            pc(1) == pc(0) + 1;
            sp(1) == sp(0) - 1;
        }
    }
}

mod vec_swap {
    pub fn constraint_stage_1() {
        let is_first = super::common::on_first_row();
        let is_last = super::common::on_last_row();
        if is_first {
            step_counter(0) == 3;
        }
        stack_pop_index(0) == sp(0);
        stack_pop_sub_index(0) == 0;
        stack_pop_value_header(0) == false;
        // stack_pop_version(0) < clk(0);

        super::common::require_no_stack_push();
        super::common::require_no_local_op();

        frame_index(1) == frame_index(0);
        module_index(1) == module_index(0);
        function_index(1) == function_index(0);
        pc(1) == pc(0);
        opcode(1) == opcode(0);
        aux0(1) == aux0(0);
        aux1(1) == aux1(0);
        sp(1) == sp(0) - 1;

        if is_last {
            requre_next_state("vec_swap_stage2");
        }
    }

    // move value at index1/index2 to stack
    pub fn constraint_stage_2_or_3(is_stage_2: bool) {
        declare!(index1, index2, value_len, ref_local_sub_index);
        super::common::require_no_stack_pop();

        // stack push
        stack_push_index(0) == sp(0) + 1;
        if is_first {
            stack_push_sub_index(0) == 0;
        }

        if is_first {
            if stack_push_value_header(0) == true {
                (value_len(0), step_counter(0)) == stack_push_value(0);
            } else {
                step_counter(0) == 1;
            }
        }
        stack_push_version(0) == clk(0);

        // local constraints
        if is_stage_2 {
            if is_first {
                (local_frame_index(0), local_index(0))
                    == stack_pop_value(-1).as_reference().index();
                ref_local_sub_index(0) == stack_pop_value(-1).as_reference().sub_index();
            }
        };
        local_sub_index(0)
            == concat(
                ref_local_sub_index(0),
                if is_stage_2 { index1 } else { index2 },
                nonzero(stack_push_sub_index(0)),
            );
        local_read_value(0) == stack_push_value(0);
        local_read_value_header(0) == stack_push_value_header(0);
        local_read_value_invalid(0) == false;
        // local_read_version(0) < clk(0);
        local_write_value_invalid(0) == true;
        local_write_version(0) == clk(0);

        // next row
        frame_index(1) == frame_index(0);
        module_index(1) == module_index(0);
        function_index(1) == function_index(0);
        pc(1) == pc(0);
        opcode(1) == opcode(0);
        aux0(1) == aux0(0);
        aux1(1) == aux1(0);

        sp(1) == if is_last { sp(0) + 1 } else { sp(0) };

        local_frame_index(1) == local_frame_index(0);
        local_index(1) == local_index(0);
        ref_local_sub_index(1) = ref_local_sub_index(0);
        index1(1) == index1(0);
        index2(1) == index2(0);
    }

    // pop stack, and write to index1/index2
    pub fn constraint_stage_4_or_5<const FOUR: bool>() {
        declare!(index1, index2, value_len, ref_local_sub_index);
        super::common::require_no_stack_push();

        // stack pop
        stack_pop_index(0) == sp(0);
        if is_first {
            stack_pop_sub_index(0) == 0;
        } else {
            // NOTICE: no need to make sure of it.
            // stack_pop_sub_index(0).l0 != 0;
        }
        if is_first {
            if stack_pop_value_header(0) == true {
                (value_len(0), step_counter(0)) == stack_pop_value(0);
            } else {
                step_counter(0) == 1;
            }
        }
        // stack_pop_version(0) < clk(0);

        // local constraints
        // NOTICE: local_frame_index(0) and local_index(0) are constrained by prev state.
        local_sub_index(0)
            == concat(
                nonzero(ref_local_sub_index(0)),
                if FOUR { index1 } else { index2 },
                nonzero(stack_pop_sub_index(0)),
            );
        local_read_value_invalid(0) == true;
        // local_read_version(0) < clk(0);
        local_write_value_invalid(0) == false;
        local_write_value(0) == stack_pop_value(0);
        local_write_value_header(0) == stack_pop_value_header(0);
        local_write_version(0) == clk(0);

        // next row
        sp(1) == if is_last { sp(0) - 1 } else { sp(0) };
        let constraints = || {
            frame_index(1) == frame_index(0);
            module_index(1) == module_index(0);
            function_index(1) == function_index(0);
            pc(1) == pc(0);
            opcode(1) == opcode(0);
            aux0(1) == aux0(0);
            aux1(1) == aux1(0);
            local_frame_index(1) == local_frame_index(0);
            local_index(1) == local_index(0);
            ref_local_sub_index(1) = ref_local_sub_index(0);
            index1(1) == index1(0);
            index2(1) == index2(0);
        };
        if FOUR {
            constraints();
        } else {
            if !is_last {
                constraints();
            }
        }
    }
}
mod vec_pop_back {
    /// pop vector_ref from stack and update parent from up to bottom
    pub fn constraint_stage1() {
        declare!(vector_sub_index);
        let extend_sub_index_of_next_row = ExtendSubIndex::new(local_sub_index(1));
        declare!(vector_origin_len);

        super::common::require_no_stack_push();

        let is_first = super::common::on_first_row();
        let is_last = super::common::on_last_row();
        if is_first {
            stack_pop_index(0) == sp(0);
            stack_pop_sub_index(0) == 0;
            // stack_pop_version(0) < clk(0);
            (local_frame_index(0), local_index(0)) == stack_pop_value(0).as_reference().index;
            vector_sub_index(0) == stack_pop_value(0).as_reference().sub_index;
            // start from top to bottom
            local_sub_index(0) == 0;
        } else {
            super::common::require_no_stack_pop();
            local_frame_index(0) == local_frame_index(-1);
            local_index(0) == local_index(-1);
            vector_sub_index(0) == vector_sub_index(-1);
            // local_sub_index(0)
        }
        if !is_last {
            local_sub_index(0) == extend_sub_index_of_next_row.parent();
        } else {
            local_sub_index(0) == vector_sub_index(0);
        }
        local_read_value_header(0) == true;
        local_read_value_invalid(0) == false;
        local_write_value_header(0) == true;
        local_write_value_invalid(0) == false;
        // local_read_version(0) < clk(0);
        local_write_version(0) == clk(0);

        if !is_last {
            // the delta should be the same for not-last-row
            local_read_value(0).as_header().flen - local_write_value(0).as_header().flen
                == local_read_value(1).as_header().flen - local_write_value(1).as_header().flen;
            local_read_value(0).as_header().len == local_write_value(0).as_header().len;
        } else {
            // for last row,  the delta is (old_len-1, old_flen - elem_flen)
            local_read_value(0).as_header().flen
                == local_write_value(0).as_header().flen + step_counter(1);
            local_read_value(0).as_header().len == local_write_value(0).as_header().len() + 1;
            vector_origin_len(0) == local_read_value(0).as_header().len;
        }

        // next
        frame_index(1) == frame_index(0);
        module_index(1) == module_index(0);
        function_index(1) == function_index(0);
        pc(1) == pc(0);
        opcode(1) == opcode(0);
        aux0(1) == aux0(0);
        aux1(1) == aux1(0);
        sp(1) == sp(0);
    }
    /// move value from local to stack
    pub fn constraint_stage2() {
        declare!(vector_sub_index);
        let extend_vector_sub_index = ExtendSubIndex::new(vector_sub_index(0));
        declare!(vector_origin_len);

        super::common::require_no_stack_pop();

        let is_first = super::common::on_first_row();
        let is_last = super::common::on_last_row();

        vector_origin_len(0) == vector_origin_len(-1);

        vector_sub_index(0) == vector_sub_index(-1);
        local_frame_index(0) == local_frame_index(-1);
        local_index(0) == local_index(-1);
        local_sub_index(0)
            == extend_vector_sub_index.concat(vector_origin_len(0) + stack_push_sub_index(0) << 16);

        if is_first {
            if local_read_value_header(0) {
                step_counter(0) == local_read_value(0).as_header().flen;
            } else {
                step_counter(0) == 1;
            }
        }
        local_write_value(0) == INVALID;
        local_read_value_invalid(0) == false;
        local_write_value_invalid(0) == true;
        local_write_value_header(0) == local_read_value_header(0);
        // local_read_version(0) < clk(0);
        local_write_version(0) == clk(0);

        stack_push_index(0) == sp(0);
        if is_first {
            // make sure sub_index of first is zero.
            stack_push_sub_index(0) == 0;
        } else {
            // NOTICE: not needed
            // stack_push_sub_index(0) > stack_push_sub_index(-1);
        }
        stack_push_value(0) == local_read_value(0);
        stack_push_value_header(0) == local_read_value_header(0);
        stack_push_version(0) == clk(0);

        // next
        frame_index(1) == frame_index(0);
        module_index(1) == module_index(0);
        function_index(1) == function_index(0);
        sp(1) == sp(0);
        if is_last {
            pc(1) == pc(0) + 1;
        } else {
            pc(1) == pc(0);
            opcode(1) == opcode(0);
            aux0(1) == aux0(0);
            aux1(1) == aux1(0);
        }
    }
}

// vec_push_back have same constraints structures as vec_pop_back with minimal changes
mod vec_push_back {
    /// pop vector_ref from stack and update parent from up to bottom
    pub fn constraint_stage1() {
        declare!(vector_sub_index);
        let extend_sub_index_of_next_row = ExtendSubIndex::new(local_sub_index(1));
        declare!(vector_origin_len);

        super::common::require_no_stack_push();

        let is_first = super::common::on_first_row();
        let is_last = super::common::on_last_row();
        if is_first {
            stack_pop_index(0) == sp(0);
            stack_pop_sub_index(0) == 0;
            // stack_pop_version(0) < clk(0);
            (local_frame_index(0), local_index(0)) == stack_pop_value(0).as_reference().index;
            vector_sub_index(0) == stack_pop_value(0).as_reference().sub_index;
            // start from top to bottom
            local_sub_index(0) == 0;
        } else {
            super::common::require_no_stack_pop();
            local_frame_index(0) == local_frame_index(-1);
            local_index(0) == local_index(-1);
            vector_sub_index(0) == vector_sub_index(-1);
            // local_sub_index(0)
        }
        if !is_last {
            local_sub_index(0) == extend_sub_index_of_next_row.parent();
        } else {
            local_sub_index(0) == vector_sub_index(0);
        }
        local_read_value_header(0) == true;
        local_read_value_invalid(0) == false;
        local_write_value_header(0) == true;
        local_write_value_invalid(0) == false;
        // local_read_version(0) < clk(0);
        local_write_version(0) == clk(0);

        if !is_last {
            // the delta should be the same for not-last-row
            local_write_value(0).as_header().flen - local_read_value(0).as_header().flen
                == local_write_value(1).as_header().flen - local_read_value(1).as_header().flen;
            local_read_value(0).as_header().len == local_write_value(0).as_header().len;
        } else {
            // for last row the delta is (old_len+1, old_flen + elem_flen)
            local_read_value(0).as_header().len + 1 == local_write_value(0).as_header().len;
            local_read_value(0).as_header().flen + step_counter(1)
                == local_write_value(0).as_header().flen;
            vector_origin_len(0) == local_read_value(0).as_header().len;
        }

        // next
        frame_index(1) == frame_index(0);
        module_index(1) == module_index(0);
        function_index(1) == function_index(0);
        pc(1) == pc(0);
        opcode(1) == opcode(0);
        aux0(1) == aux0(0);
        aux1(1) == aux1(0);
        sp(1) == sp(0);
    }
    /// move value from stack to local
    pub fn constraint_stage2() {
        declare!(vector_sub_index);
        let extend_vector_sub_index = ExtendSubIndex::new(vector_sub_index(0));
        declare!(vector_origin_len);

        super::common::require_no_stack_push();

        let is_first = super::common::on_first_row();
        let is_last = super::common::on_last_row();

        vector_origin_len(0) == vector_origin_len(-1);
        vector_sub_index(0) == vector_sub_index(-1);
        local_frame_index(0) == local_frame_index(-1);
        local_index(0) == local_index(-1);
        local_sub_index(0)
            == extend_vector_sub_index
                .concat(vector_origin_len(0) + 1 + stack_pop_sub_index(0) << 16);

        if is_first {
            if local_write_value_header(0) {
                step_counter(0) == local_write_value(0).as_header().flen;
            } else {
                step_counter(0) == 1;
            }
        }
        local_read_value_invalid(0) == true;
        local_write_value_invalid(0) == false;
        // local_read_version(0) < clk(0);
        local_write_version(0) == clk(0);

        stack_pop_index(0) == sp(0) - 1;
        if is_first {
            // make sure sub_index of first is zero.
            stack_pop_sub_index(0) == 0;
        } else {
            // NOTICE: not needed
            // stack_pop_sub_index(0) > stack_pop_sub_index(-1);
        }
        stack_pop_value(0) == local_write_value(0);
        stack_pop_value_header(0) == local_write_value_header(0);
        // stack_pop_version(0) < clk(0);

        // next
        frame_index(1) == frame_index(0);
        module_index(1) == module_index(0);
        function_index(1) == function_index(0);

        if is_last {
            pc(1) == pc(0) + 1;
            sp(1) == sp(0) - 2; // decrease 2 as the opcode pop 2 elems
        } else {
            pc(1) == pc(0);
            opcode(1) == opcode(0);
            aux0(1) == aux0(0);
            aux1(1) == aux1(0);
            sp(1) == sp(0);
        }
    }
}

// Native Poseidon hash function
mod native_poseidon_hash {
    /// Native Poseidon hash function specification
    /// Takes two U128 values from stack and produces one U256 hash result
    /// Stack effect: pops 2, pushes 1 (net: SP -= 1)
    pub fn constrain() {
        if super::common::on_first_row() {
            // Two-step execution: first pop rhs, then pop lhs and push result
            step_counter(0) == 2;
            super::common::require_no_stack_push();

            // First step: pop the right-hand side operand from top of stack
            stack_pop_index(0) == sp(0);
            sp(1) == sp(0); // Keep sp unchanged during first step
        }

        // Common constraints for both steps
        stack_pop_sub_index(0) == 0;
        stack_pop_value_header(0) == false;
        // stack_pop_version(0) < clk(0);
        super::common::require_no_local_op();

        if super::common::on_last_row() {
            // Second step: pop lhs and push hash result
            stack_pop_index(0) == sp(0) - 1;
            stack_push_index(0) == sp(0) - 1;
            stack_push_sub_index(0) == 0;

            // Get the two input values
            let rhs = stack_pop_value(-1); // First popped value (from previous step)
            let lhs = stack_pop_value(0); // Second popped value (current step)

            // Compute hash using native function
            let hash_result = native_poseidon_hash(lhs, rhs);

            // Push the hash result
            stack_push_value(0) == hash_result;
            stack_push_value_header(0) == false;
            stack_push_version(0) == clk(0);

            // State transitions
            module_index(1) == module_index(0);
            function_index(1) == function_index(0);
            frame_index(1) == frame_index(0);
            pc(1) == pc(0) + 1;
            sp(1) == sp(0) - 1; // Net decrease: 2 pops - 1 push = -1
        }
    }
}
