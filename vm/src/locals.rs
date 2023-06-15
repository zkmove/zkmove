// Copyright (c) zkMove Authors

use error::{RuntimeError, StatusCode, VmResult};
use halo2_proofs::arithmetic::FieldExt;
use movelang::value::{
    AddressPath, FrameIndex, LocalLocation, LocalRef, LocatedValue, PrimitiveValue, Value,
    ValueLocation,
};
use movelang::word::LocatedWord;
use std::ops::Deref;
use std::{cell::RefCell, rc::Rc};
use vm_circuit::witness::rw_operations::{LocalsOp, RWOperation, RW};

#[derive(Clone)]
pub struct Locals<F: FieldExt>(Vec<Rc<RefCell<Value<F>>>>);

impl<F: FieldExt> Locals<F> {
    pub fn new(size: usize) -> Self {
        Self(
            vec![Value::Invalid; size]
                .into_iter()
                .map(|v| Rc::new(RefCell::new(v)))
                .collect(),
        )
    }

    pub fn copy(
        &self,
        index: usize,
        frame_index: usize,
        rw_operations: &mut Vec<RWOperation<F>>,
    ) -> VmResult<Value<F>> {
        match self.0.get(index) {
            Some(v) => {
                if matches!(&*v.borrow(), Value::Invalid) {
                    Err(RuntimeError::new(StatusCode::CopyLocalError))
                } else {
                    let copied_value = v.borrow().copy_value();
                    let word: LocatedWord<F> = LocatedValue(
                        ValueLocation::Local(LocalLocation {
                            frame_index: FrameIndex(frame_index),
                            index,
                        }),
                        &copied_value,
                    )
                    .into();

                    emit_locals_ops_for_word(word, RW::READ, rw_operations);
                    Ok(copied_value)
                }
            }
            None => Err(RuntimeError::new(StatusCode::OutOfBounds)),
        }
    }

    pub fn store(
        &self,
        index: usize,
        value: Value<F>,
        frame_index: usize,
        rw_operations: &mut Vec<RWOperation<F>>,
    ) -> VmResult<()> {
        match self.0.get(index) {
            Some(v) => {
                if let Value::Container(c) = &*v.borrow() {
                    if c.rc_count() > 1 {
                        return Err(
                            RuntimeError::new(StatusCode::UnknownInvariantViolationError)
                                .with_message(
                                    "moving container with dangling references".to_string(),
                                ),
                        );
                    }
                }
                let word: LocatedWord<F> = LocatedValue(
                    ValueLocation::Local(LocalLocation {
                        frame_index: FrameIndex(frame_index),
                        index,
                    }),
                    &value,
                )
                .into();
                emit_locals_ops_for_word(word, RW::WRITE, rw_operations);
                *v.borrow_mut() = value;
                Ok(())
            }
            None => Err(RuntimeError::new(StatusCode::OutOfBounds)),
        }
    }

    pub fn move_(
        &self,
        index: usize,
        frame_index: usize,
        rw_operations: &mut Vec<RWOperation<F>>,
    ) -> VmResult<Value<F>> {
        let value_cell = self
            .0
            .get(index)
            .ok_or_else(|| RuntimeError::new(StatusCode::OutOfBounds))?;
        let old_value = value_cell.replace(Value::Invalid); // Invalidate Local
        match old_value {
            Value::Invalid => Err(RuntimeError::new(StatusCode::MoveLocalError)),
            v => {
                let word: LocatedWord<F> = LocatedValue(
                    ValueLocation::Local(LocalLocation {
                        frame_index: FrameIndex(frame_index),
                        index,
                    }),
                    &v,
                )
                .into();
                // LocalsOP Read
                emit_locals_ops_for_word(word.clone(), RW::READ, rw_operations);
                // LocalsOP Write
                for (address_path, _) in word.0 {
                    let locals_op_2 = LocalsOp {
                        frame_index: *address_path
                            .0
                            .first()
                            .expect("frame_index should not be None")
                            as usize,
                        index: *address_path.0.get(1).expect("index should not be None") as usize,
                        address_ext_0: address_path.addr_ext(),
                        value: None,
                        rw: RW::WRITE,
                        gc: rw_operations.len(),
                    };
                    rw_operations.push(RWOperation::LocalsOp(locals_op_2));
                }

                Ok(v)
            }
        }
    }

    pub fn borrow_locals(
        &self,
        index: usize,
        frame_index: usize,
        rw_operations: &mut Vec<RWOperation<F>>,
    ) -> VmResult<LocalRef<F>> {
        let value_cell = self
            .0
            .get(index)
            .ok_or_else(|| RuntimeError::new(StatusCode::OutOfBounds))?;
        let value_ref = value_cell.borrow();
        let v = value_ref.deref();
        match v {
            Value::Invalid => Err(RuntimeError::new(StatusCode::MutBorrowLocalError)),
            Value::U8(_)
            | Value::U64(_)
            | Value::U128(_)
            | Value::Bool(_)
            | Value::Address(_)
            | Value::Container(_) => {
                let loc = LocalLocation {
                    frame_index: FrameIndex(frame_index),
                    index,
                };
                let word: LocatedWord<F> = LocatedValue(ValueLocation::Local(loc), v).into();
                emit_locals_ops_for_word(word, RW::READ, rw_operations);
                Ok(LocalRef {
                    loc,
                    refer: value_cell.clone(),
                })
            }
            _ => unimplemented!(),
        }
    }

    pub fn read_ref(
        &self,
        index: usize,
        frame_index: usize,
        rw_operations: &mut Vec<RWOperation<F>>,
    ) -> VmResult<Value<F>> {
        let value_cell = self
            .0
            .get(index)
            .ok_or_else(|| RuntimeError::new(StatusCode::OutOfBounds))?;
        let loc = LocalLocation {
            frame_index: FrameIndex(frame_index),
            index,
        };
        match &*value_cell.borrow() {
            Value::Invalid => Err(RuntimeError::new(StatusCode::ImmBorrowLocalError)),
            v => {
                let word: LocatedWord<F> = LocatedValue(ValueLocation::Local(loc), v).into();
                emit_locals_ops_for_word(word, RW::READ, rw_operations);
                Ok(v.copy_value())
            }
        }
    }
}

impl<F: FieldExt> Locals<F> {
    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

pub fn emit_locals_op<F: FieldExt>(
    address_path: AddressPath<F>,
    value: PrimitiveValue<F>,
    rw: RW,
    rw_operations: &mut Vec<RWOperation<F>>,
) {
    let locals_op = LocalsOp {
        frame_index: *address_path
            .0
            .first()
            .expect("frame_index should not be None") as usize,
        index: *address_path.0.get(1).expect("index should not be None") as usize,
        address_ext_0: address_path.addr_ext(),
        value: Some(value),
        rw,
        gc: rw_operations.len(),
    };
    rw_operations.push(RWOperation::LocalsOp(locals_op));
}

#[allow(clippy::type_complexity)]
pub fn emit_locals_ops_for_word<F: FieldExt>(
    word: LocatedWord<F>,
    rw: RW,
    rw_operations: &mut Vec<RWOperation<F>>,
) {
    for (address_path, val) in word.0 {
        emit_locals_op(address_path, val, rw, rw_operations)
    }
}
