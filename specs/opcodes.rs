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
            opcode(1) = opcode(0);
            //sp(1) == sp(0);
        } else {
            step_counter(0) == 1;

            // if opcode(0) != CALL && opcode(0) != RET {
            //     module_index(1) == module_index(0);
            //     function_index(1) == function_index(0);
            //     frame_index(1) == frame_index(0);
            //     pc(1) == pc(0) + 1;
            // }
        }
        stack_pop_version(0) < clk(0);
    }

    pub fn fake_local_read_zero() {
        local_frame_index(0) == 0;
        local_index(0) == 0;
        local_sub_index(0) == 0;
        local_read_value(0) == 0;
        local_write_value(0) == 0;
        local_write_version(0) > local_read_version(0); //TODO: can we just set the versions to be 0?
    }

    /// Opcode context state transition steps except the last
    fn context_state_transition() {
        module_index(1) == module_index(0);
        function_index(1) == function_index(0);
        frame_index(1) == frame_index(0);
        pc(1) == pc(0);
        sp(1) == sp(0);
        opcode(1) = opcode(0);
        step_counter(1) == step_counter(0) - 1;
    }

    pub fn fake_empty_stack_pop(offset: usize) {}
    pub fn fake_empty_stack_push(offset: usize) {}
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

mod ld {
    fn constraint_ld() {
        table_opcode.contain(pc(0), opcode(0), aux0(0));
        // Memory Context Constraints:
        stack_push_index(0) == sp(0) + 1;
        stack_push_sub_index(0) == 0;
        stack_push_value(0) == aux0(0);
        stack_push_value_header(0) == false;
        stack_push_version(0) == clk(0);
        // Local Context Constraints: fake local memory operation.
        super::common::fake_local_read_zero();

        sp(1) == sp(0) + 1;
        module_index(1) == module_index(0);
        function_index(1) == function_index(0);
        frame_index(1) == frame_index(0);
        pc(1) == pc(0) + 1;
    }
}
mod ldu256 {
    fn constraint_ldu256() {
        let is_first = super::common::on_first_row();
        let is_last = super::common::on_last_row();
        if is_first {
            // first row of current step
            step_counter(0) == 3; // ld u256 contains three rows
            table_opcode.contain(pc(0), opcode(0), aux0(0));
            stack_push_sub_index(0) == 0;
            stack_push_value(0) == (2, 3); // len=2,flen=3
            stack_push_value_header(0) == true;
        } else {
            // if the opcode contain multi rows.
            stack_push_sub_index(0) == stack_push_sub_index(-1) + 1;
            stack_push_value(0) == if is_last { aux1(0) } else { aux0(0) }; // (lo, hi)
            stack_push_value_header(0) == false;
        }
        stack_push_index(0) == sp(0) + 1;
        stack_push_version(0) == clk(0);

        if is_last {
            sp(1) == sp(0) + 1;
        } else {
            // next row within same opcode
            sp(1) == sp(0);
            aux0(1) == aux0(0);
            aux1(1) == aux1(0);
            // decrease step_counter
            step_counter(1) == step_counter(0) - 1;
        }

        /// Local Context Constraints: fake local memory operation.
        super::common::fake_local_read_zero();
    }
}

mod pop {
    fn constraint_pop() {
        let is_first = super::common::on_first_row();
        let is_last = super::common::on_last_row();

        if is_first {
            table_opcode.contain(pc(0), opcode(0), aux0(0), aux0(1));
            stack_pop_sub_index(0) == 0; // simple value or header
                                         // TODO: reduce to is_last
            let is_simple = step_counter(0) == 1;
            if !is_simple {
                // !simple value
                let (len, flen) = stack_pop_value(0);
                step_counter(0) == flen; // need to constraint flen == step_counter in the first row.
            }
        }
        stack_pop_index(0) = sp(0);
        stack_pop_version(0) < clk(0);
        super::common::fake_empty_stack_push();
        super::common::fake_local_read_zero();

        if is_last {
            sp(1) == sp(0) - 1;
        } else {
            sp(1) == sp(0);
            aux0(1) == aux0(0);
            aux1(1) == aux1(0);
            step_counter(1) == step_counter(0) - 1;
            //stack_sub_index(1) > stack_sub_index(0);
        }
    }
}

// TODO: support u256
mod add {
    fn constraint_add() {
        let is_first = super::common::on_first_row();
        let is_last = super::common::on_last_row();

        if is_first {
            // first row
            table_opcode.contain(pc(0), opcode(0), aux0(0), aux0(1));
            step_counter(0) == 2;
            super::common::fake_empty_stack_push();
        } else {
            stack_push_index(0) == stack_pop_index(0);
            stack_push_sub_index(0) == stack_pop_sub_index(0);
            // TODO: add overflow check
            // second row is write a+b to a
            stack_push_value(0) == stack_pop_value(0) + stack_pop_value(-1);
            stack_push_value_header(0) == false;
            stack_push_version(0) == clk(0);
            stack_push_version(0) > stack_pop_version(0);
        }
        stack_pop_index(0) == sp(0);
        stack_pop_sub_index(0) == 0;

        super::common::fake_local_read_zero();

        if is_last {
            sp(1) == sp(0);
        } else {
            aux0(1) == aux0(0);
            aux1(1) == aux1(0);
            sp(1) == sp(0) - 1;
            step_counter(1) == step_counter(0) - 1;
        }
    }
}

// TODO: u256 support
mod le {
    fn constraint_le() {
        let is_first = super::common::on_first_row();
        let is_last = super::common::on_last_row();

        if is_first {
            // first row
            table_opcode.contain(pc(0), opcode(0), aux0(0), aux0(1));
            step_counter(0) == 2;
            // first row is write invalid to b,
        } else {
            stack_push_index(0) == stack_pop_index(0);
            stack_push_sub_index(0) == stack_pop_sub_index(0);
            // second row is write `a<b` to a
            let is_le = stack_pop_value(0) <= stack_pop_value(-1);
            stack_push_value(0) == is_le;
            stack_push_value_header(0) == false;
            stack_push_version(0) == clk(0);
            stack_push_version(0) > stack_pop_version(0);
        }
        stack_pop_index(0) == sp(0);
        stack_pop_sub_index(0) == 0;

        super::common::fake_local_read_zero();

        if is_last {
            sp(1) == sp(0);
        } else {
            aux0(1) == aux0(0);
            aux1(1) == aux1(0);
            sp(1) == sp(0) - 1;
            step_counter(1) == step_counter(0) - 1;
        }
    }
}

// TODO: Reference type value comparison, actually it can convert to (pop,pop,read_ref,read_ref,push)
mod eq {
    pub fn constrain() {
        if super::common::on_first_row() {
            constrain_first();
        } else {
            constrain_remain();
        }

        if !super::common::on_last_row() {
            step_counter(1) == step_counter(0) - 1;
            sp(1) == sp(0);
        } else {
            sp(1) == sp(0) - 1;
        }
    }

    fn constrain_first() {
        table_opcode.contain(pc(0), EQ, 0);

        let flen_b = if !stack_pop_value_header(0) {
            1
        } else {
            stack_pop_value(0).flen
        };
        let flen_a = if !stack_pop_value_header(1) {
            1
        } else {
            stack_pop_value(1).flen
        };
        step_counter(0) == flen_b + flen_a + diff(flen_b, flen_a);

        field_counter(0) == flen_b;
        field_counter(1) == flen_a;
        is_odd(0) == 1;
        is_odd(1) == 0;

        stack_pop_index(0) == sp(0);
        stack_pop_index(1) == sp(0) - 1;
        stack_pop_sub_index(0) == 0;
        stack_pop_sub_index(1) == 0;
        stack_pop_version(0) < clk(0);
        stack_pop_version(1) < clk(0);

        stack_push_index(0) == sp(0) - 1;
        stack_push_sub_index(0) == 0;
        stack_push_value(0) == intermediate_result(0);
        stack_push_value_header(0) == false;
        stack_push_version(0) == clk(0);

        super::common::fake_empty_stack_push(1);
        super::common::fake_local_read_zero(0);
        super::common::fake_local_read_zero(1); //next row

        let is_equal = (
            stack_pop_sub_index(0),
            stack_pop_value(0),
            stack_pop_value_header(0),
        ) == (
            stack_pop_sub_index(1),
            stack_pop_value(1),
            stack_pop_value_header(1),
        );
        if step_counter(0) == 2 {
            //both a and b are simple value
            intermediate_result(0) == is_equal;
        } else {
            intermediate_result(0) == is_equal && intermediate_result(2);
        }
    }

    fn constrain_remain() {
        let is_last = super::common::on_last_row();
        !is_last && is_odd(1) == is_odd(-1);

        if field_counter(0) > 1 {
            field_counter(2) == field_counter(0) - 1;
        } else {
            if is_odd(0) == 1 && field_counter(1) > 1 {
                field_counter(2) == 0;
            }
            if is_odd(0) == 0 && field_counter(-1) > 1 {
                field_counter(2) == 0;
            }
        }

        if is_odd(0) == 1 {
            if field_counter(0) != 0 {
                //normal stack pop
                stack_pop_index(0) == sp(0);
                stack_pop_sub_index(0) == 0;
                stack_pop_version(0) == stack_pop_version(-2);
            } else {
                super::common::fake_empty_stack_pop(0);
            }

            if field_counter(1) != 0 {
                //normal stack pop
                stack_pop_index(1) == sp(0) - 1;
                stack_pop_sub_index(1) == 0;
                stack_pop_version(1) == stack_pop_version(-1);
            } else {
                super::common::fake_empty_stack_pop(1); //next row
            }

            super::common::fake_empty_stack_push(0);
            super::common::fake_local_read_zero(0);
            super::common::fake_empty_stack_push(1); //next row
            super::common::fake_local_read_zero(1); //next row

            // constrain intermediate_result
            let is_equal = (
                stack_pop_sub_index(0),
                stack_pop_value(0),
                stack_pop_value_header(0),
            ) == (
                stack_pop_sub_index(1),
                stack_pop_value(1),
                stack_pop_value_header(1),
            );
            if step_counter(1) == 1 {
                //last pair
                intermediate_result(0) == is_equal;
            } else {
                intermediate_result(0) == is_equal && intermediate_result(2);
            }
        }
    }
}

mod not {
    pub fn constrain() {
        table_bytecode.lookup(pc(0), opcode(0), aux0(0), aux1(0));

        stack_pop_index(0) == sp(0);
        stack_push_index(0) == sp(0);
        stack_pop_sub_index(0) == 0;
        stack_push_sub_index(0) == 0;
        stack_push_value(0) = !stack_pop_value(0);
        stack_push_value_header(0) == false;
        stack_push_version(0) == clk(0);
        stack_pop_version(0) < clk(0);

        sp(1) == sp(0);
        super::common::fake_local_read_zero(0);
    }
}

mod cast {
    pub fn constrain() {
        table_bytecode.lookup(pc(0), opcode(0), aux0(0), aux1(0));

        stack_pop_index(0) == stack_push_index(0) && stack_push_index(0) == sp(0);
        stack_pop_sub_index(0) == 0;
        stack_push_sub_index(0) == 0;
        stack_push_value(0) = stack_pop_value(0);
        stack_push_value_header(0) == false;
        stack_push_version(0) == clk(0);
        stack_pop_version(0) < clk(0);

        sp(1) == sp(0);
        super::common::fake_local_read_zero(0);
    }
}

// TODO: support smart contract return value
mod ret {
    pub fn constrain() {
        table_opcode.contain(pc(0), Opcode::Ret, 0);

        super::common::fake_empty_stack_pop(0);
        super::common::fake_empty_stack_push(0);
        super::common::fake_local_read_zero(0);

        // constrain Opcode Context of the next step
        if frame_index == 0 {
            opcode(1) == Opcode::Nop || opcode(1) == Opcode::Stop;
            pc(1) == pc(0);
        } else {
            // not the first frame, lookup call table to constrain next pc
            table_call.contain(
                EntryType::RET,
                module_index(0),
                function_index(0),
                pc(0),
                module_index(1),
                function_index(1),
                pc(1),
            );
        }
    }
}

// define new column field_counter(reuse aux1), to record the number of members sitll
// need to be processed. when local_index and field_counter both equal to 1, we will
// go into the last step
// TODO: add (function_instantiataion_index, arg_num) into table_func
mod call {
    pub fn constrain() {
        if super::common::on_first_row() {
            table_func.contain(aux0(0), arg_num); //aux0 is callee function_instantiation_index
            table_opcode.contain(pc(0), CALL, aux0(0));
            local_index(0) == arg_num;
            if aug_num != 0 {
                stack_pop_sub_index(0) == 0; //the first step must pop a simple value or a header
            } else {
                step_counter(0) == 1;
            }
        }

        if !super::common::on_last_row() {
            stack_pop_index(0) == sp(0);
            stack_pop_value(0) == local_write_value(0);
            stack_pop_value_header(0) == local_write_value_header(0);
            stack_pop_sub_index(0) == local_sub_index(0);
            local_frame_index(0) == frame_index(0) + 1; //write to local of next frame
            local_write_version(0) == clk(0);
            common::local_write_first_time(0); //TODO:constrain local_read_version
            super::common::fake_empty_stack_push(0);

            let is_simple = stack_pop_sub_index(0) == 0 && !stack_pop_value_header(0);
            let is_header = stack_pop_sub_index(0) == 0 && stack_pop_value_header(0);

            if is_simple {
                field_counter(0) == 1;
            } else if is_header {
                field_counter(0) == stack_pop_value(0).f_len;
            }

            let end_of_one_arg = field_counter(0) == 1;
            if is_simple || end_of_one_arg {
                local_index(1) == local_index(0) - 1;
                sp(1) == sp(0) - 1;
                stack_pop_sub_index(1) == 0;
                stack_pop_version(1) < clk(0);
            } else {
                local_index(1) == local_index(0);
                sp(1) == sp(0);
                field_counter(1) == field_counter(0) - 1;
                stack_pop_version(1) == stack_pop_version(0);
            }

            step_counter(1) == step_counter(0) - 1;
            // all args processed
            if local_index(0) == 1 && field_counter(0) == 1 {
                step_counter(1) == 1;
            }
        }

        if super::common::on_last_row() {
            super::common::fake_empty_stack_pop();
            super::common::fake_empty_stack_push();
            super::common::fake_local_read_zero();
            pc(1) == 0;
            sp(1) == sp(0);
            table_call.contain(
                EntryType::CALL,
                module_index(0),
                function_index(0),
                pc(0),
                module_index(1),
                function_index(1),
                pc(1),
            );
        }
    }
}

mod move_loc {
    fn constraint() {
        let is_first = super::common::on_first_row();
        let is_last = super::common::on_last_row();

        if is_first {
            // first row
            table_opcode.contain(pc(0), opcode(0), aux0(0), aux0(1));
            local_sub_index(0) == 0; // simple value or header
            if !is_last {
                // !simple value
                let (len, flen) = stack_read_value(0);
                step_counter(0) == flen; // need to constraint flen == step_counter in the first row.
            }
        }

        stack_push_index(0) == sp(0) + 1; // push a value onto stack
        local_frame_index(0) == frame_index(0);
        local_index(0) == aux0(0); // ensure local_index equal to operand0
        local_sub_index(0) == stack_push_sub_index(0);
        local_read_value(0) == stack_push_value(0);
        local_read_value_header(0) == stack_push_value_header(0);
        lcoal_read_value(0) != INVALID;
        local_write_value(0) == INVALID; // move_loc will invalidate origin local slot.
                                         // constraint local-invalidating has the same write_version
        local_write_version(0) == clk(0);
        local_write_version(0) > local_read_version(0);
        stack_push_version == clk(0);

        if is_last {
            sp(1) == sp(0) + 1;
        } else {
            sp(1) == sp(0);
            aux0(1) == aux0(0);
            aux1(1) == aux1(0);
            step_counter(1) == step_counter(0) - 1;
            //local_sub_index(1) > local_sub_index(0); // make sure sub_index of complex value is increasing.
        }
    }
}

mod copy_loc {
    fn constraint() {
        let is_first = super::common::on_first_row();
        let is_last = super::common::on_last_row();

        if is_first {
            // first row
            table_opcode.contain(pc(0), opcode(0), aux0(0), aux0(1));
            local_sub_index(0) == 0; // simple value or header
            if !is_last {
                // !simple value
                let (len, flen) = stack_read_value(0);
                step_counter(0) == flen; // need to constraint flen == step_counter in the first row.
            }
        }

        stack_push_index(0) == sp(0) + 1; // push a value onto stack
        local_frame_index(0) == frame_index(0);
        local_index(0) == aux0(0); // ensure local_index equal to operand0
        local_sub_index(0) == stack_push_sub_index(0);
        lcoal_read_value(0) != INVALID;
        local_read_value(0) == stack_push_value(0);
        local_read_value_header(0) == stack_push_value_header(0);
        local_write_value(0) == local_read_value(0); // copy_loc will just read data, this the only difference with move_loc
        local_write_value_header(0) == local_read_value_header(0);
        // constraint local-invalidating has the same write_version
        local_write_version(0) == clk(0);
        local_write_version(0) > local_read_version(0);
        stack_push_version == clk(0);

        if is_last {
            sp(1) == sp(0) + 1;
        } else {
            sp(1) == sp(0);
            aux0(1) == aux0(0);
            aux1(1) == aux1(0);
            step_counter(1) == step_counter(0) - 1;
            //local_sub_index(1) > local_sub_index(0); // make sure sub_index of complex value is increasing.
        }
    }
}

mod store_loc {
    fn constraint() {
        let is_first = super::common::on_first_row();
        let is_last = super::common::on_last_row();

        if is_first {
            // first row
            table_opcode.contain(pc(0), opcode(0), aux0(0), aux0(1));

            stack_pop_sub_index(0) == 0;

            // constraint w_flen.
            w_flen(0) != 0; // ensure w_flen > 0 in first row
            let is_complex_value = w_flen(0) != 1; // TODO: should change to use HEADER flag?
            if is_complex_value {
                // complex value
                let (len, flen) = stack_pop_value(0);
                w_flen(0) == flen; // need to constraint flen == step_counter in the first row.
            }

            // constraint step_counter
            let invalidate_old = local_write_version(0) != 0;
            if invalidate_old && local_read_value_header {
                let (len, flen) = local_read_value(0);
                step_counter(0) == w_flen(0) + flen - 1; // step counter should be the old_local_value_flen+new_local_value_flen - 1
            } else {
                step_counter(0) == w_flen(0); // if old value is simple or store_to_empty, we donnt need to invalidate.
            }
        }
        let in_store_stage = w_flen(0) != 0;
        // in this stage, we copy stack value into local, and invalidate stack.
        if in_store_stage {
            stack_pop_index(0) == sp(0); // write invalid to current stack
                                         // !is_first_row && stack_sub_index(0) > stack_sub_index(-1); // make sure value sub_index increasing.
            stack_pop_version(0) < clk(0);
            local_frame_index(0) == frame_index(0);
            local_index(0) == aux0(0); // ensure local_index equal to operand0
            local_sub_index(0) == stack_pop_sub_index(0);
            // local_read_value(0) should be either INVALID or the latest value based on the version of local_write_version
            local_write_value(0) == stack_pop_value(0);
            local_write_value_header(0) == stack_pop_value_header(0);

            local_write_version(0) == clk(0);
            clk(0) > local_read_version(0);
            // !is_first_row && local_read_value(0) == INVALID; // if not first row, local_read old_value should be INVALID.
        }

        let in_invalidate_local_stage = w_flen(0) == 0;
        if in_invalidate_local_stage {
            local_frame_index(0) == frame_index(0);
            local_index(0) == aux(0);
            local_sub_index(0) != 0; // not header
            local_read_value(0) != INVALID;
            local_write_value(0) == INVALID;
            // we constraint that version only increase 1 in invalid stage.
            local_read_version(0) + 1 = local_write_version(0);
            // or we can
            // clk(0) - 1 = local_write_version(0);
        }

        // constraint next row,
        // iterate each columns to add constraint.

        if is_last {
            sp(1) == sp(0) - 1;
        } else {
            sp(1) == sp(0);
            aux0(1) == aux0(0);
            aux1(1) == aux1(0);
            step_counter(1) == step_counter(0) - 1;
            if in_store_stage {
                w_flen(1) == w_flen(0) - 1;
            }
            if in_invalidate_local_stage {
                w_flen(1) == w_flen(0); // == 0
            }
            // if in_invalidate_local_stage {
            //     local_sub_index(1) > local_sub_index(0);
            // }
        }
    }
}

mod borrow_loc {
    pub fn constrain() {
        if super::common::on_first_row() {
            table_bytecode.lookup(pc(0), opcode(0), aux0(0), aux1(0));
            step_counter(0) == 4;
            stack_push_value(0) == (3, 4);
            stack_push_value_header(0) == true;
            stack_push_sub_index(0) == 0;
            // second row
            stack_push_value(1) = frame_index(0);
        }

        if !super::common::on_first_row() {
            stack_push_value_header(0) == false;
        }

        stack_push_index(0) == sp(0) + 1;
        stack_push_version(0) == clk(0);
        super::common::fake_empty_stack_pop(0);
        super::common::fake_local_read_zero(0);

        if !super::common::on_last_row() {
            stack_push_sub_index(1) == stack_push_sub_index(0) + 1;
            sp(1) == sp(0);
        } else {
            // third row
            stack_push_value(-1) = aux0(0);
            // last row
            stack_push_value(0) = 0;
            stack_push_sub_index(0) == 3;

            module_index(1) == module_index(0);
            function_index(1) == function_index(0);
            frame_index(1) == frame_index(0);
            pc(1) == pc(0) + 1;
            sp(1) == sp(0) + 1;
        }
    }
}

mod borrow_field {
    pub fn constrain() {
        if common::on_first_row() {
            step_counter(0) == 4;
            stack_push_value_header(0) == true;
        } else {
            stack_push_value_header(0) == false;
        }

        stack_pop_index(0) == sp(0);
        stack_pop_version(0) < clk(0);
        stack_push_index(0) == sp(0);
        stack_pop_sub_index(0) == 4 - step_counter(0);
        stack_push_sub_index(0) == stack_pop_sub_index(0);
        stack_push_version(0) == clk(0);
        sp(1) == sp(0);
        super::common::fake_local_read_zero(0);

        if !common::on_last_row() {
            stack_pop_value(0) == stack_push_value(0);
        } else  {
            //fh_idx starts from 0, but sub_index starts from 1, so add 1 on aux0
            stack_push_value(0) == stack_pop_value(0).concat(aux0(0)+1);
            module_index(1) == module_index(0);
            function_index(1) == function_index(0);
            frame_index(1) == frame_index(0);
            pc(1) == pc(0) + 1;
        }
    }
}

mod read_ref {
    pub fn constrain_read_ref_stage_1() {
        if super::common::on_first_row() {
        opcode(0) == OpCode::READ_REF;
        step_counter(0) == 4;
    }

        stack_pop_index(0) == sp(0);
        stack_pop_sub_index(0) == 4 - step_counter(0);
        super::common::fake_empty_stack_push();
        super::common::fake_local_read_zero();

        if !super::common::on_last_row() {
            sp(1) == sp(0);
        }

        if super::common::on_last_row() {
            module_index(1) == module_index(0);
            function_index(1) == function_index(0);
            frame_index(1) == frame_index(0);
            pc(1) == pc(0);
            sp(1) == sp(0) - 1;
            execution_state_next == ReadRefStage2;
        }
    }
    pub fn constrain_read_ref_stage_2() {
        if super::common::on_first_row() {
            // first step in the stage
            execution_state_prev == read_ref_stage_1;

            if local_read_value_header(0) {
                step_counter(0) == local_read_value(0).f_len;
            } else {
                step_counter(0) == 1;
            }

            local_frame_index(0) == stack_pop_value(-3);
            local_index(0) == stack_pop_value(-2);
            local_sub_index(0) == stack_pop_value(-1);
            // record the sub index of the referenced value's header
            header_sub_index(0) == local_sub_index(0);
        }

        stack_push_index(0) == sp(0) + 1;
        super::common::constrain_sub_index(
            header_sub_index(0),
            stack_push_sub_index(0),
            depth(0),
            local_sub_index(0),
        );
        stack_push_value(0) == local_read_value(0);
        stack_push_value_header(0) == local_read_value_header(0);
        stack_push_version(0) == clk(0);
        local_read_version(0) < clk(0);
        local_write_value(0) == local_read_value(0);
        local_write_value_header(0) == local_read_value_header(0);
        local_write_value_invalid(0) == local_read_value_invalid(0);
        local_write_version(0) == clk(0);
        super::common::fake_empty_stack_pop();

        if super::common::not_last_row() {
            // non-last step
            local_frame_index(1) == local_frame_index(0);
            local_index(1) == local_index(0);
            header_sub_index(1) == header_sub_index(0);
            sp(1) == sp(0);
        }

        if super::common::on_last_row() {
            module_index(1) == module_index(0);
            function_index(1) == function_index(0);
            frame_index(1) == frame_index(0);
            pc(1) == pc(0) + 1;
            sp(1) == sp(0) + 1;
        }
    }
}

mod write_ref {
    //STAGE_POP_REF
    pub fn constrain_write_ref_stage_1() {
        if super::common::on_first_row() {
            opcode(0) == OpCode::WRITE_REF;
            step_counter(0) == 4;
        }

        stack_pop_index(0) == sp(0);
        stack_pop_sub_index(0) == 4 - step_counter(0);
        super::common::fake_empty_stack_push();
        super::common::fake_local_read_zero();

        if !super::common::on_last_row() {
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

    //STAGE_INVALIDATE_OLD
    pub fn constrain_write_ref_stage_2() {
        if super::common::on_first_row() {
            execution_state_prev == WriteRefStage1;

            local_frame_index(0) == stack_pop_value(-3);
            local_index(0) == stack_pop_value(-2);
            local_sub_index(0) == stack_pop_value(-1);
            step_counter(0) == local_read_value(0).f_len;
            // record the sub index of the referenced value,
            // for updating parent header later
            header_sub_index(0) == local_sub_index(0);
            header_flen_delta(0) == local_read_value(0).f_len;
        }

        if !super::common::on_first_row() {
            SubIndexGadget::configure_membership(header_sub_index(0), local_sub_index(0));
        }

        local_read_version(0) < clk(0);
        local_write_value(0) == Invalid; // write 0
        local_write_value_invalid(0) == true;
        local_write_value_header == false;
        local_write_version(0) == clk(0);
        super::common::fake_empty_stack_pop();
        super::common::fake_empty_stack_push();
        // sp always the same, even for last row
        sp(1) == sp(0);

        if !super::common::on_last_row() {
            local_frame_index(1) == local_frame_index(0);
            local_index(1) == local_index(0);
            header_sub_index(1) == header_sub_index(0);
            header_flen_delta(1) == header_flen_delta(0);
        }

        if super::common::on_last_row() {
            module_index(1) == module_index(0);
            function_index(1) == function_index(0);
            frame_index(1) == frame_index(0);
            pc(1) == pc(0);
            execution_state_next == WriteRefStage3;
        }
    }

    //STAGE_WRITE_NEW
    pub fn constrain_write_ref_stage_3() {
        if super::common::on_first_row() {
            execution_state_prev == WriteRefStage2;
            step_counter(0) == stack_pop_value(0).f_len;
            header_sub_index(0) == header_sub_index(-1);
            header_flen_delta(0) == stack_pop_value(0).f_len - header_flen_delta(-1);

            stack_pop_sub_index(0) == 0;
            local_frame_index(0) == local_frame_index(-1);
            local_index(0) == local_index(-1);
        }

        stack_pop_index(0) == sp(0);
        stack_pop_version(0) < clk(0);
        SubIndexGadget::configure_sub_index_concact(header_sub_index(0), stack_pop_sub_index(0), local_sub_index(0));
        local_read_value(0) == Invalid;
        local_read_value_invalid(0) == true;
        local_read_version(0) < clk(0);
        local_write_value(0) == stack_pop_value(0);
        local_write_value_header(0) == stack_pop_value_header(0);
        local_write_version(0) == clk(0);
        super::common::fake_empty_stack_push(0);

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
            pc(1) == pc(0);
            sp(1) == sp(0) - 1;
            execution_state_next == WriteRefStage4;
        }
    }

    //STAGE_UPDATE_PARENT
    pub fn constrain_write_ref_stage_4() {
        if super::common::on_first_row() {
            execution_state_prev == WriteRefStage3;
            step_counter(0) == header_sub_index(-1).depth();
            header_sub_index(0) == header_sub_index(-1) / 2 ^ 16;
            header_flen_delta(0) == header_flen_delta(-1);
            local_frame_index(0) == local_frame_index(-1);
            local_index(0) == local_index(-1);
        }

        local_read_version(0) < clk(0);
        local_sub_index(0) == header_sub_index(0);
        local_write_value(0) == local_read_value(0) + header_flen_delta(0);
        local_write_value_header(0) == local_read_value_header(0);
        local_write_value_invalid(0) == local_read_value_invalid(0);
        local_write_version(0) == clk(0);
        // sp always the same, even for last row
        sp(1) == sp(0);

        if !super::common::on_last_row() {
            header_sub_index(1) == header_sub_index(0) / 2 ^ 16;
            header_flen_delta(1) == header_flen_delta(0);
            local_frame_index(1) == local_frame_index(0);
            local_index(1) == local_index(0);
        }
        if super::common::on_last_row() {
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
        stack_pop_version(0) < clk(0);
        let cond = stack_pop_value(0);
        super::common::fake_empty_stack_push();
        super::common::fake_local_read_zero();

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

        super::common::fake_empty_stack_pop();
        super::common::fake_empty_stack_push();
        super::common::fake_local_read_zero();

        sp(1) == sp(0);
        pc(1) == aux0(0);
    }
}

mod pack {
    pub fn constrain() {
        if super::common::on_first_row() {
            let flen = step_counter(0);
            let num_field = aux0(0);
            stack_push_index(0) == sp(0) - num_field + 1;
            stack_push_sub_index(0) == 0;
            stack_push_value(0) == (num_field, flen);
            stack_push_value_header(0) == true;
            stack_push_version(0) == clk(0);

            super::common::fake_empty_stack_pop();
            super::common::fake_local_read_zero();

            field_idx(1) == aux0(0);
            stack_pop_index(1) == sp(0);
            stack_pop_sub_index(1) == 0;
            stack_pop_version(1) < clk(0);
        }

        if !super::common::on_first_row() {
            if stack_pop_sub_index(0) == 0 {
                if !stack_pop_value_header(0) {
                    field_counter(0) == 1;
                }
                if stack_pop_value_header(0) {
                    field_counter(0) == stack_pop_value(0).f_len;
                }
            }

            stack_push_value(0) == stack_pop_value(0);
            stack_push_value_header(0) == stack_pop_value_header(0);
            field_index(0) == lower_two_types(field_index(0)); //field_index < 2^16;
            stack_push_sub_index(0) == stack_pop_sub_index(0) << 16 + field_idx(0);
            stack_push_version(0) == clk(0);
            super::common::fake_local_read_zero(0);

            if !super::common::on_last_row() {
                let end_of_one_field = field_counter(0) == 1;
                if end_of_one_field {
                    field_index(1) == field_index(0) - 1;
                    stack_pop_index(1) == stack_pop_index(0) - 1;
                    stack_pop_sub_index(1) == 0;
                    stack_pop_version(1) < clk(0);
                } else {
                    field_index(1) == field_index(0);
                    stack_pop_index(1) == stack_pop_index(0);
                    stack_pop_version(1) == stack_pop_version(0);
                    field_counter(1) == field_counter(0) - 1;
                }
            }
        }

        if !super::common::on_last_row() {
            stack_push_index(1) == stack_push_index(0);
            step_counter(1) == step_counter(0) - 1;
            sp(1) == sp(0);
        }

        if super::common::on_last_row() {
            // all fields processed
            field_idx(0) == 1 && field_counter(0) == 1;

            sp(1) == stack_push_index(0);
            // module_index(1) == module_index(0);
            // function_index(1) == function_index(0);
            // frame_index(1) == frame_index(0);
            // pc(1) == pc(0) + 1;
        }
    }
}

mod unpack {
    fn constraint() {
        let is_first_row = super::common::on_first_row();
        let on_last_row = super::common::on_last_row();
        if is_first_row {
            // first row of current step
            stack_pop_sub_index(0) == 0;
            stack_pop_value(0) == (num_field(0), step_counter(0));
            field_index(0) == aux(0) + 1;
            field_counter(0) == 1;
        }
        stack_pop_index(0) == sp(0);
        stack_pop_version(0) < clk(0);
        if !is_first_row {
            stack_push_index(0) == sp(0) + field_index(0) - 1;
            stack_push_sub_index(0) << 16 + field_index(0) == stack_pop_index(0);
            stack_push_value(0) == stack_pop_value(0);
            stack_push_value_header(0) == stack_pop_value_header(0);
            stack_push_version(0) == clk(0);
        }

        if field_counter(0) == 1 {
            // 在上一个元素的结束时，约束下一个元素的field_counter
            if field_index(0) != 1 {
                field_index(1) == field_index(0) - 1;
                // 保证 subindex 是第  field_index 个元素的header
                stack_pop_sub_index(1).to_u16_vec() == vec![0, 0, 0, 0, 0, 0, 0, field_index(1)];
                if !stack_pop_value_header(1) {
                    field_counter(1) == 1;
                } else {
                    let (len, flen) = stack_pop_value(1);
                    field_counter(1) == flen;
                }
            }
        } else {
            field_counter(1) == field_counter(0) - 1;
            field_index(1) == field_index(0);
        }

        if on_last_row {
            field_index(0) == 1;
            field_counter(0) == 1;
            sp(1) == sp(0) + aux0(0) - 1; // sp(0)+num_field-1
        } else {
            aux0(1) == aux0(0);
            aux1(1) == aux1(0);
            sp(1) == sp(0);
            step_counter(1) == step_counter(0) - 1;
        }
    }
}

// define column field_idx (reusing column aux0)
// define column value_menber_counter (reusing column aux1)
mod vec_pack {
    pub fn constrain() {
        if super::common::on_first_row() {
            constrain_header();
        } else {
            constrain_remain();
        }
    }
    fn constrain_header() {
        table_bytecode.lookup(pc(0), VEC_PACK, field_idx(0));

        let flen = step_counter(0);
        stack_push_index(0) == sp(0) - num_field(0) + 1;
        stack_push_sub_index(0) == 0;
        stack_push_value(0) == (num_field, flen);
        stack_push_value_header(0) == true;
        stack_push_version(0) == clk(0);

        field_idx(1) == field_idx(0);
        stack_pop_index(1) == sp(0);
        stack_pop_sub_index(1) == 0;
        stack_pop_version(1) < clk(0);
        stack_push_index(1) == stack_push_index(0);

        module_index(1) == module_index(0);
        function_index(1) == function_index(0);
        pc(1) == pc(0);
        sp(1) == sp(0);
        opcode(1) == opcode(0);
        //clk(1) == clk(0);
    }

    fn constrain_remain() {
        let is_simple = stack_pop_sub_index(0) == 0 && !stack_pop_value_header(0);
        let is_header = stack_pop_sub_index(0) == 0 && stack_pop_value_header(0);
        if is_simple {
            field_counter(0) == 1;
        } else if is_header {
            field_counter(0) == stack_pop_value(0).f_len;
        }

        stack_push_value(0) == stack_pop_value(0);
        stack_push_value_header(0) == stack_pop_value_header(0);
        field_index(0) == lower_two_types(field_index(0)); //field_index < 2^16;
        stack_push_sub_index(0) == stack_pop_sub_index(0) << 16 + field_idx(0);
        stack_push_version(0) == clk(0);
        super::common::fake_local_read_zero(0);

        // all fields processed
        if field_idx(0) == 1 && field_counter(0) == 1 {
            step_counter(0) == 1;
        }

        if !super::common::on_last_row() {
            let end_of_one_field = field_counter(0) == 1;
            if end_of_one_field {
                field_index(1) == field_index(0) - 1;
                stack_pop_index(1) == stack_pop_index(0) - 1;
                stack_pop_sub_index(1) == 0;
                stack_pop_version(1) < clk(0);
                stack_push_index(1) == stack_push_index(0);
            } else {
                field_index(1) == field_index(0);
                stack_pop_index(1) == stack_pop_index(0);
                stack_pop_version(1) == stack_pop_version(0);
                stack_push_index(1) == stack_push_index(0);
                field_counter(1) == field_counter(0) - 1;
            }

            sp(1) == sp(0);
            step_counter(1) == step_counter(0) - 1;
        } else {
            sp(1) == stack_push_index(0);
        }
    }
}

mod vec_unpack {
    fn constraint() {
        let is_first_row = super::common::on_first_row();
        let on_last_row = super::common::on_last_row();
        if is_first_row {
            // first row of current step
            stack_pop_sub_index(0) == 0;
            stack_pop_value(0) == (num_field(0), step_counter(0));
            field_index(0) == aux(0) + 1;
            field_counter(0) == 1;
        }
        stack_pop_index(0) == sp(0);
        stack_pop_version(0) < clk(0);
        if !is_first_row {
            stack_push_index(0) == sp(0) + field_index(0) - 1;
            stack_push_sub_index(0) << 16 + field_index(0) == stack_pop_index(0);
            stack_push_value(0) == stack_pop_value(0);
            stack_push_value_header(0) == stack_pop_value_header(0);
            stack_push_version(0) == clk(0);
        }

        if field_counter(0) == 1 {
            if field_index(0) != 1 {
                field_index(1) == field_index(0) - 1;
                stack_pop_sub_index(1).to_u16_vec() == vec![0, 0, 0, 0, 0, 0, 0, field_index(1)];
                if !stack_pop_value_header(1) {
                    field_counter(1) == 1;
                } else {
                    let (len, flen) = stack_pop_value(1);
                    field_counter(1) == flen;
                }
            }
        } else {
            field_counter(1) == field_counter(0) - 1;
            field_index(1) == field_index(0);
        }

        if on_last_row {
            field_index(0) == 1;
            field_counter(0) == 1;
            sp(1) == sp(0) + aux0(0) - 1; // sp(0)+num_field-1
        } else {
            sp(1) == sp(0);
            aux0(1) == aux0(0);
            aux1(1) == aux1(0);
            step_counter(1) == step_counter(0) - 1;
        }
    }
}

mod vec_len {
    pub fn constrain() {
        let is_first = super::common::on_first_row();
        let is_last = super::common::on_last_row();
        // pop ref
        if is_first {
            // first step
            table_bytecode.lookup(pc(0), VEC_LEN, 0);
            step_counter(0) == 4;
            stack_pop_index(0) == sp(0);
            stack_pop_sub_index(0) == 0;
            stack_pop_version(0) < clk(0);
        } else {
            stack_pop_index(0) == sp(0);
            stack_pop_sub_index(0) == stack_pop_sub_index(-1) + 1;
            stack_pop_version(0) == stack_pop_version(-1);
        }

        if !is_last {
            super::common::fake_empty_stack_push();
            super::common::fake_local_read_zero();

            sp(1) == sp(0);
            step_counter(1) == step_counter(0) - 1;
        } else {
            // read vec header
            local_frame_index(0) == stack_pop_value(-2);
            local_index(0) == stack_pop_value(-1);
            local_sub_index(0) == stack_pop_value(0);
            local_write_value(0) == local_read_value(0);
            local_write_value_header(0) == local_read_value_header(0);
            local_write_value_invalid(0) == local_read_value_invalid(0);
            local_read_version(0) < clk(0);
            local_write_version(0) == clk(0);

            // push length
            stack_push_index(0) == sp(0);
            stack_push_sub_index(0) == 0;
            stack_push_value(0) == local_read_value(0).len;
            stack_push_value_header(0) == false;
            stack_push_version(0) == clk(0);

            sp(1) == sp(0);
        }
    }
}

mod vec_borrow {
    pub fn constrain() {
        let is_first = super::common::on_first_row();
        let is_last = super::common::on_last_row();
        // first step, pop the index
        if is_first {
            table_bytecode.lookup(pc(0), VEC_BORROW, 0);
            step_counter(0) == 5;

            stack_pop_index(0) == sp(0);
            stack_pop_sub_index(0) == 0;
            stack_pop_version(0) < clk(0);
            super::common::fake_empty_stack_push();
            super::common::fake_local_read_zero();

            opcode(1) == opcode(0);
            pc(1) == pc(0);
            module_index(1) == module_index(0);
            function_index(1) == function_index(0);
            step_counter(1) == step_counter(0) - 1;
            //clk(1) == clk(0);
            sp(1) == sp(0) - 1;
            stack_pop_sub_index(1) == 0;
        }

        // middle steps
        if !is_first && !is_last {
            stack_pop_index(0) == sp(0);
            //stack_pop_sub_index is constrained by the last step
            stack_push_sub_index(0) == stack_pop_sub_index(0);
            stack_push_value(0) == stack_pop_value(0);
            stack_push_value_header(0) == stack_pop_value_header(0);
            if step_counter(0) == 4 {
                stack_pop_version(0) < clk(0);
            } else {
                stack_pop_version(0) == stack_pop_version(-1);
            }
            stack_push_version(0) = clk(0);
            super::common::fake_local_read_zero();

            sp(1) == sp(0);
            stack_pop_sub_index(1) == stack_pop_sub_index(0) + 1;
            step_counter(1) == step_counter(0) - 1;
        }

        // last step
        if is_last {
            stack_pop_index(0) == sp(0);
            stack_push_index(0) == stack_pop_index(0);
            stack_push_sub_index(0) == stack_pop_sub_index(0);
            super::common::constrain_depth(stack_pop_value(0), depth(0));
            super::common::constrain_sub_index(
                stack_pop_value(0),
                stack_pop_value(-4),
                depth(0),
                stack_push_value(0),
            );
            stack_push_value_header(0) == stack_pop_value_header(0);
            stack_pop_version(0) == stack_pop_version(-1);
            stack_push_version(0) = clk(0);
            super::common::fake_local_read_zero();

            sp(1) == sp(0);
        }
    }
}

mod vec_swap {
    pub fn constraint_stage_1() {
        let is_first = super::common::on_first_row();
        let is_last = super::common::on_last_row();
        if is_first {
            step_counter(0) == 2;
        }
        stack_pop_index(0) == sp(0);
        stack_pop_sub_index(0) == 0;
        stack_pop_value(0) != INVALID;
        stack_pop_value_flag(0) == SIMPLE;

        fake_stach_push();
        fake_local_read_zero();

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

    pub fn constraint_stage_2() {
        let is_first = super::common::on_first_row();
        let is_last = super::common::on_last_row();
        if is_first {
            // initialize the step_counter of the stage
            let (len, flen) = stack_pop_value(0);
            flen == 4;
            step_counter(0) == flen; // in fact, it should always 4.
            stack_pop_value_flag(0) == HEADER_FLAG;
        } else {
            stack_pop_value_flag(0) == SIMPLE_FLAG;
        }
        // sub_index is 0,1,2,3, so just use step_counter to constrain it.
        stack_pop_sub_index(0) == 4 - step_counter(0);
        stack_pop_index(0) == sp(0);
        fake_stach_push();
        fake_local_read_zero();

        // todo: enable them for vec_swap as a whole
        frame_index(1) == frame_index(0);
        module_index(1) == module_index(0);
        function_index(1) == function_index(0);
        pc(1) == pc(0);
        opcode(1) == opcode(0);
        aux0(1) == aux0(0);
        aux1(1) == aux1(0);

        if is_last {
            requre_next_state("vec_swap_stage3");
            sp(1) == sp(0) - 1;
        } else {
            sp(1) == sp(0);
        }
    }

    // move value at index1/index2 to stack
    pub fn constraint_stage_3_or_4(is_stage_3: bool) {
        declare!(index1, index2, value_len, ref_local_sub_index);
        no_stack_pop();
        // stack push
        stack_push_index(0) == sp(0) + 1;
        if is_first {
            stack_push_sub_index(0) == 0;
        }

        if is_first {
            stack_push_value_header(0) == true;
            (value_len(0), step_counter(0)) == stack_push_value(0);
        }
        stack_push_version(0) == clk(0);

        // local constraints
        if is_stage_3 {
            if is_first {
                local_frame_index(0) == stack_pop_value(-3);
                local_index(0) == stack_pop_value(-2);
                ref_local_sub_index(0) == stack_pop_value(-1);
            }
        };
        local_sub_index(0)
            == concat(
                ref_local_sub_index(0),
                if is_stage_3 { index1 } else { index2 },
                nonzero(stack_push_sub_index(0)),
            );
        local_read_value(0) == stack_push_value(0);
        local_read_value_header(0) == stack_push_value_header(0);
        local_read_value_invalid(0) == false;
        local_read_version(0) < clk(0);
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
    pub fn constraint_stage_5<const FIVE: bool>() {
        declare!(index1, index2, value_len, ref_local_sub_index);
        no_stack_push();

        // stack pop
        stack_pop_index(0) == sp(0);
        if is_first {
            stack_pop_sub_index(0) == 0;
        } else {
            // NOTICE: no need to make sure of it.
            // stack_pop_sub_index(0).l0 != 0;
        }
        if is_first {
            stack_pop_value_header(0) == true;
            (value_len(0), step_counter(0)) == stack_pop_value(0);
        }
        stack_pop_version(0) < clk(0);

        // local constraints
        // NOTICE: local_frame_index(0) and local_index(0) are constrained by prev state.
        local_sub_index(0)
            == concat(
                nonzero(ref_local_sub_index(0)),
                if FIVE { index1 } else { index2 },
                nonzero(stack_pop_sub_index(0)),
            );
        local_read_value_invalid(0) == true;
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
        if FIVE {
            constraints();
        } else {
            if !is_last {
                constraints();
            }
        }
    }
}
mod vec_pop_back {
    const STAGE_POP_REF: u64 = 3;
    const STAGE_WRITE_HEADER: u64 = 2;
    const STAGE_WRITE_STACK: u64 = 1;
    const STAGE_NUM: u64 = 3;
    pub fn constraint() {
        let is_first = super::common::on_first_row();
        let is_last = super::common::on_last_row();
        if stage(0) == STAGE_POP_REF {
            // pop ref from stack
            if step_counter(-1) == 1 {
                // initialize the step_counter of the stage
                let (len, flen) = stack_pop_value(0);
                flen == 4;
                step_counter(0) == flen; // in fact, it should always 4.
                stack_pop_sub_index(0) == 0;
                stack_pop_value_header(0) == true;
            } else {
                stack_pop_value_header(0) == false;
            }

            stack_pop_index(0) == sp(0);
            stack_pop_value(0) != INVALID;
            stack_pop_version(0) < clk(0);
            fake_local_read_zero();
        }
        //Fixme? ref could be an IndexedRef, it may have more than one parents
        if stage(0) == STAGE_WRITE_HEADER {
            step_counter(0) == 1;

            fake_stack_read_zero();

            local_frame_index(0) == stack_pop_value(-3);
            local_index(0) == stack_pop_value(-2);
            local_sub_index(0) == stack_pop_value(-1);
            local_write_version(0) == clk(0);
            local_write_version(0) > local_read_version(0);
        }
        // init ref_sub_index
        stage(0) == STAGE_WRITE_HEADER
            && step_counter(0) == 1
            && ref_sub_index(0) == local_sub_index(0);
        stage(0) < STAGE_WRITE_HEADER && ref_sub_index(0) == ref_sub_index(-1);

        if stage(0) == STAGE_WRITE_STACK {
            if step_counter(-1) == 1 {
                // firt row of the stage

                let (pop_elem_len, pop_elem_flen) = if !local_read_value_header(0) {
                    (1, 1)
                } else {
                    local_read_value(0)
                };
                // constraint vec len and flen
                let (old_len, old_flen) = local_read_value(-1);
                let (new_len, new_flen) = local_write_value(-1);
                old_len == new_len + 1; // pop elem
                old_flen == new_flen + pop_elem_flen;

                step_counter(0) == pop_elem_flen;

                // FIXME: fix the sub_index constraint
                //local_sub_index(0) == ref_sub_index(0) * 16 + old_len; // pop the last elem
                local_sub_index(0) == ref_sub_index(0) + old_len << (depth(0) * 16);
                // if ref is IndexedRef, we need introduce an advise 'depth' to indicate the ref's depth
                super::common::constrain_depth(ref_sub_index(0), depth(0));
            }
            local_frame_index(0) == local_frame_index(-1);
            local_index(0) == local_index(-1);
            local_read_value(0) != INVALID;
            local_write_value(0) == INVALID;
            local_write_version(0) > local_read_version(0);
            local_write_version(0) == clk(0);

            stack_push_index(0) == sp(0);
            // FIXME: we should move the sub_index out of the vector.
            //stack_push_sub_index(0) == local_sub_index(0) - ref_sub_index(0) * 16;
            stack_push_sub_index(0) == local_sub_index(0) >> ((depth(0) + 1) * 16);
            stack_push_value(0) == local_read_value(0);
            stack_push_version(0) == clk(0);
        }

        // init stage and step_counter
        is_first && stage(0) == STAGE_NUM;

        // Constraint next row's counter
        // constraint next row's step_counter and stage.
        if step_counter(0) == 1 {
            if stage(0) != 1 {
                stage(1) == stage(0) - 1;
            }
        } else {
            stage(1) == stage(0);
            step_counter(1) == step_counter(0) - 1;
        }

        // sp always the same
        sp(1) == sp(0);
        if is_last {
            stage(0) == 1;
        } else {
            aux0(1) == aux0(0);
            aux1(1) == aux1(0);
        }
    }
}

mod vec_push_back {
    const STAGE_POP_REF: u64 = 3;
    const STAGE_WRITE_HEADER: u64 = 2;
    const STAGE_WRITE_LOCAL: u64 = 1;
    const STAGE_NUM: u64 = 3;
    pub fn constraint() {
        let is_first = super::common::on_first_row();
        let is_last = super::common::on_last_row();

        if stage(0) == STAGE_POP_REF {
            let is_first = step_counter(-1) == 1;
            // pop ref from stack
            if is_first {
                // initialize the step_counter of the stage
                let (len, flen) = stack_pop_value(0);
                flen == 4;
                step_counter(0) == flen; // in fact, it should always 4.
                stack_pop_sub_index(0) == 0;
                stack_pop_value_header(0) == true;
            } else {
                stack_pop_value_header(0) == false;
            }
            stack_pop_index(0) == sp(0);
            stack_pop_value(0) != INVALID;
            stack_pop_version(0) < clk(0);
            fake_local_read_zero();
        }

        //Fixme? ref could be an IndexedRef, it may have more than one parents
        if stage(0) == STAGE_WRITE_HEADER {
            step_counter(0) == 1;

            fake_stack_read_zero();

            local_frame_index(0) == stack_pop_value(-3);
            local_index(0) == stack_pop_value(-2);
            local_sub_index(0) == stack_pop_value(-1);
            local_write_version(0) == clk(0);
            local_write_version(0) > local_read_version(0);
        }
        // init ref_sub_index
        stage(0) == STAGE_WRITE_HEADER
            && step_counter(0) == 1
            && ref_sub_index(0) == local_sub_index(0);
        stage(0) < STAGE_WRITE_HEADER && ref_sub_index(0) == ref_sub_index(-1);

        if stage(0) == STAGE_WRITE_LOCAL {
            let is_first = step_counter(-1) == 1;
            if is_first {
                // firt row of the stage

                let (pop_elem_len, pop_elem_flen) = if !stack_pop_value_header(0) {
                    (1, 1)
                } else {
                    stack_pop_value(0)
                };
                // constraint vec len and flen
                let (old_len, old_flen) = local_read_value(-1);
                let (new_len, new_flen) = local_write_value(-1);
                old_len + 1 == new_len; // push elem
                old_flen + pop_elem_flen == new_flen;

                step_counter(0) == pop_elem_flen;
            }
            stack_pop_index(0) == sp(0);
            is_first && stack_pop_sub_index(0) == 0;
            // !is_first && stack_sub_index(0) > stack_sub_index(-1);
            stack_pop_value(0) != INVALID;
            stack_pop_version(0) < clk(0);

            local_frame_index(0) == local_frame_index(-1);
            local_index(0) == local_index(-1);
            // if ref is IndexedRef, we need introduce an advise 'depth' to indicate the ref's depth
            super::common::constrain_depth(ref_sub_index(0), depth(0));
            local_sub_index(0)
                == ref_sub_index(0) + new_len
                    << (depth(0) * 16) + stack_pop_sub_index(0)
                    << ((depth(0) + 1) * 16);

            local_write_value(0) == stack_pop_value(0);
            local_write_version(0) == clk(0);
            local_read_version(0) < local_write_version(0);
        }

        // init stage and step_counter
        is_first && stage(0) == STAGE_NUM;

        // Constraint next row's counter
        // constraint next row's step_counter and stage.
        if step_counter(0) == 1 {
            if stage(0) != 1 {
                stage(1) == stage(0) - 1;
            }
        } else {
            stage(1) == stage(0);
            step_counter(1) == step_counter(0) - 1;
        }

        // constraint sp
        if super::common::on_first_row() {
            sp(0) == sp(-1) - 1;
        }
        if stage(0) == STAGE_WRITE_HEADER
        /* && step_counter(-1) == 1 */
        {
            // write_header only has one row
            // first row of write_header
            sp(0) == sp(-1) + 1;
        } else {
            sp(0) == sp(-1);
        }

        // constraint next row's opcode context
        if is_last {
            stage(0) == 1;
            sp(1) == sp(0) - 2;
        } else {
            aux0(1) == aux0(0);
            aux1(1) == aux1(0);
        }
    }
}
