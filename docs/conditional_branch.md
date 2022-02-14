We introduce program block to handle the conditional branch.
```
pub struct Block<F: FieldExt> {
    pc: u16,
    start: u16,
    end: Option<u16>,
    locals: Locals<F>,
    code: Vec<Bytecode>,
    condition: Option<F>,
}

pub struct Branch<F: FieldExt> {
    pub block: Block<F>,
    pub is_running: bool, //which arm of conditional branch is running
}

pub struct ConditionalBlock<F: FieldExt> {
    pub true_branch: Option<Branch<F>>,
    pub false_branch: Option<Branch<F>>,
}

pub enum ProgramBlock<F: FieldExt> {
    Block(Block<F>),
    ConditionalBlock(ConditionalBlock<F>),
}
```
Example of conditional branch (1)
```
#0, LdU8(0)
#1, StLoc(2)
#2, LdU8(1)
#3, StLoc(3)
#4, CopyLoc(2)
#5, CopyLoc(3)
#6, Eq
#7, BrTrue(9)
#8, Branch(14)

#9, CopyLoc(2)
#10, CopyLoc(3)
#11, Add
#12, StLoc(1)
#13, Branch(18)

#14, CopyLoc(2)
#15, CopyLoc(3)
#16, Mul
#17, StLoc(1)

#18, MoveLoc(1)
#19, Pop
#20, Ret
```
Example of conditional branch (2)
```
#0, LdU8(0)
#1, StLoc(2)
#2, LdU8(0)
#3, StLoc(3)
#4, CopyLoc(0)
#5, CopyLoc(1)
#6, Eq
#7, BrTrue(9)
#8, Branch(19)

#9, CopyLoc(0)
#10, CopyLoc(1)
#11, Add
#12, StLoc(2)
#13, CopyLoc(0)
#14, CopyLoc(1)
#15, Add
#16, LdU8(1)
#17, Add
#18, StLoc(3)

#19, CopyLoc(2)
#20, CopyLoc(3)
#21, Add
#22, Pop
#23, Ret
```
Example of conditional branch (3)
```
#0, CopyLoc(0)
#1, LdU8(1)
#2, Sub
#3, StLoc(3)
#4, CopyLoc(3)
#5, LdU8(1)
#6, Eq
#7, StLoc(1)
#8, MoveLoc(1)
#9, BrTrue(12)

#10, LdU64(101)
#11, Abort

#12, CopyLoc(3)
#13, LdU8(1)
#14, Add
#15, Pop
#16, Ret
```

