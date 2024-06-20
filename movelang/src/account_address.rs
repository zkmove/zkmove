// Copyright (c) The Move Contributors
// Copyright (c) zkMove Authors

use move_core_types::account_address::AccountAddress as MoveAccountAddress;
use move_core_types::u256::U256;
use types::Field;

#[derive(Default, Clone, Copy, Ord, PartialOrd, PartialEq, Eq, Debug)]
pub struct AccountAddress(pub u128);

impl AccountAddress {
    pub fn new(value: u128) -> Self {
        Self(value)
    }
    pub fn value(&self) -> u128 {
        self.0
    }
    pub fn field_value<F: Field>(&self) -> F {
        F::from_u128(self.0)
    }
    pub fn zero() -> Self {
        MoveAccountAddress::ZERO.into()
    }
    pub fn one() -> Self {
        MoveAccountAddress::ONE.into()
    }
    pub fn copy(&self) -> Self {
        Self(self.value())
    }
}

impl From<MoveAccountAddress> for AccountAddress {
    fn from(addr: MoveAccountAddress) -> AccountAddress {
        // FIXME, if the struct is not needed, delete then. or else fix the api
        Self(U256::from_le_bytes(&addr.into_bytes()).unchecked_as_u128())
    }
}

impl From<AccountAddress> for MoveAccountAddress {
    fn from(addr: AccountAddress) -> MoveAccountAddress {
        MoveAccountAddress::from(U256::from(addr.0).to_le_bytes())
    }
}
