// Copyright (c) The Move Contributors
// Copyright (c) zkMove Authors

use halo2_proofs::arithmetic::FieldExt;
use move_core_types::account_address::AccountAddress as MoveAccountAddress;

#[derive(Default, Clone, Copy, Ord, PartialOrd, PartialEq, Eq, Debug)]
pub struct AccountAddress<F: FieldExt>(F);

impl<F: FieldExt> AccountAddress<F> {
    pub fn new(value: F) -> Self {
        Self(value)
    }
    pub fn value(&self) -> F {
        self.0
    }
}

impl<F: FieldExt> From<MoveAccountAddress> for AccountAddress<F> {
    fn from(addr: MoveAccountAddress) -> AccountAddress<F> {
        Self(F::from_u128(u128::from_le_bytes(addr.into_bytes())))
    }
}

impl<F: FieldExt> From<AccountAddress<F>> for MoveAccountAddress {
    fn from(addr: AccountAddress<F>) -> MoveAccountAddress {
        addr.value().get_lower_128().to_le_bytes().into()
    }
}
