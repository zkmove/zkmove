use crate::bytecode::Instruction;
use crate::bytecodes::*;
use crate::interpreter::Interpreter;
use bellman::pairing::bn256::{Bn256, Fr};
use crypto::constraint_system::DummyCS;

#[test]
fn test_ldu8() {
    let mut cs = DummyCS::new();
    let mut interp = Interpreter::<Bn256>::new();

    let mut bytecode: Vec<Box<dyn Instruction<Bn256, DummyCS<Bn256>>>> = Vec::new();
    bytecode.push(Box::new(LdU8(1u8)));

    match interp.run(&mut cs, &bytecode) {
        Ok(_) => {}
        Err(e) => {
            println!("runtime error: {:?}", e)
        }
    }

    let result = interp.stack().top().unwrap().value().unwrap();
    let expected = Fr::from_hex("0x01").unwrap();
    assert_eq!(result, expected, "result is not expected");
}

#[test]
fn test_pop() {
    let mut cs = DummyCS::new();
    let mut interp = Interpreter::<Bn256>::new();

    let mut bytecode: Vec<Box<dyn Instruction<Bn256, DummyCS<Bn256>>>> = Vec::new();
    bytecode.push(Box::new(LdU8(1u8)));
    bytecode.push(Box::new(LdU8(2u8)));
    bytecode.push(Box::new(Pop));

    match interp.run(&mut cs, &bytecode) {
        Ok(_) => {}
        Err(e) => {
            println!("runtime error: {:?}", e)
        }
    }

    let result = interp.stack().top().unwrap().value().unwrap();
    let expected = Fr::from_hex("0x01").unwrap();
    assert_eq!(result, expected, "result is not expected");
}

#[test]
fn test_add_u8() {
    let mut cs = DummyCS::new();
    let mut interp = Interpreter::<Bn256>::new();

    let mut bytecode: Vec<Box<dyn Instruction<Bn256, DummyCS<Bn256>>>> = Vec::new();
    bytecode.push(Box::new(LdU8(1u8)));
    bytecode.push(Box::new(LdU8(2u8)));
    bytecode.push(Box::new(Add));

    match interp.run(&mut cs, &bytecode) {
        Ok(_) => {}
        Err(e) => {
            println!("runtime error: {:?}", e)
        }
    }

    let result = interp.stack().top().unwrap().value().unwrap();
    let expected = Fr::from_hex("0x03").unwrap();
    assert_eq!(result, expected, "result is not expected");
}

#[test]
fn test_add_u64() {
    let mut cs = DummyCS::new();
    let mut interp = Interpreter::<Bn256>::new();

    let mut bytecode: Vec<Box<dyn Instruction<Bn256, DummyCS<Bn256>>>> = Vec::new();
    bytecode.push(Box::new(LdU64(1u64)));
    bytecode.push(Box::new(LdU64(2u64)));
    bytecode.push(Box::new(Add));

    match interp.run(&mut cs, &bytecode) {
        Ok(_) => {}
        Err(e) => {
            println!("runtime error: {:?}", e)
        }
    }

    let result = interp.stack().top().unwrap().value().unwrap();
    let expected = Fr::from_hex("0x03").unwrap();
    assert_eq!(result, expected, "result is not expected");
}

#[test]
fn test_add_u128() {
    let mut cs = DummyCS::new();
    let mut interp = Interpreter::<Bn256>::new();

    let mut bytecode: Vec<Box<dyn Instruction<Bn256, DummyCS<Bn256>>>> = Vec::new();
    bytecode.push(Box::new(LdU128(1u128)));
    bytecode.push(Box::new(LdU128(2u128)));
    bytecode.push(Box::new(Add));

    match interp.run(&mut cs, &bytecode) {
        Ok(_) => {}
        Err(e) => {
            println!("runtime error: {:?}", e)
        }
    }

    let result = interp.stack().top().unwrap().value().unwrap();
    let expected = Fr::from_hex("0x03").unwrap();
    assert_eq!(result, expected, "result is not expected");
}

#[test]
fn test_sub_u8() {
    let mut cs = DummyCS::new();
    let mut interp = Interpreter::<Bn256>::new();

    let mut bytecode: Vec<Box<dyn Instruction<Bn256, DummyCS<Bn256>>>> = Vec::new();
    bytecode.push(Box::new(LdU8(1u8)));
    bytecode.push(Box::new(LdU8(2u8)));
    bytecode.push(Box::new(Sub));

    match interp.run(&mut cs, &bytecode) {
        Ok(_) => {}
        Err(e) => {
            println!("runtime error: {:?}", e)
        }
    }

    let result = interp.stack().top().unwrap().value().unwrap();
    let expected = Fr::from_hex("0x01").unwrap();
    assert_eq!(result, expected, "result is not expected");
}

#[test]
fn test_mul_u8() {
    let mut cs = DummyCS::new();
    let mut interp = Interpreter::<Bn256>::new();

    let mut bytecode: Vec<Box<dyn Instruction<Bn256, DummyCS<Bn256>>>> = Vec::new();
    bytecode.push(Box::new(LdU8(1u8)));
    bytecode.push(Box::new(LdU8(2u8)));
    bytecode.push(Box::new(Mul));

    match interp.run(&mut cs, &bytecode) {
        Ok(_) => {}
        Err(e) => {
            println!("runtime error: {:?}", e)
        }
    }

    let result = interp.stack().top().unwrap().value().unwrap();
    let expected = Fr::from_hex("0x02").unwrap();
    assert_eq!(result, expected, "result is not expected");
}
