#[test_only]
module confidential_asset_sui::confidential_asset_sui_tests;

use confidential_asset_sui::token;
use verifier_api::native_verifier;
use verifier_api::serialized_params_store;

#[test]
fun test_register_initializes_balance_and_inbox() {
    let ctx = &mut tx_context::dummy();
    let store = token::register(ctx);

    assert!(token::balance_of(&store) == encrypted_zero(), 0);
    assert!(token::inbox_length(&store) == 0, 1);

    token::destroy_store(store);
}

#[test]
fun test_public_inputs_are_built_from_call_arguments() {
    let zero = scalar(0);
    let one = scalar(1);
    let two = scalar(2);
    let three = scalar(3);
    let six = scalar(6);

    assert!(
        token::encrypt_public_inputs_for_test(6) == vector[
            vector[copy zero],
            vector[copy zero],
            vector[copy six],
            vector[copy zero],
        ],
        10,
    );

    assert!(
        token::sum_public_inputs_for_test(1, 2, 3) == vector[
            vector[copy zero, copy zero, copy zero],
            vector[copy zero, copy zero, copy zero],
            vector[copy one, copy two, copy three],
            vector[copy zero, copy zero, copy zero],
        ],
        11,
    );

    assert!(
        token::range_public_inputs_for_test(1, 2, 3) == vector[
            vector[copy zero, copy zero, copy zero],
            vector[copy zero, copy zero, copy zero],
            vector[one, two, three],
            vector[copy zero, copy zero, zero],
        ],
        12,
    );
}

#[test]
fun test_u256_public_inputs_split_into_low_and_high_words() {
    let zero = scalar(0);
    let one = scalar(1);
    let six = scalar(6);
    let value = (1u256 << 128) + 6;

    assert!(
        token::encrypt_public_inputs_for_test(value) == vector[
            vector[copy zero],
            vector[copy zero],
            vector[six],
            vector[one],
        ],
        20,
    );
}

#[test]
#[expected_failure]
fun test_mint_builds_public_inputs_and_rejects_invalid_proof() {
    let ctx = &mut tx_context::dummy();
    let params = serialized_params_store::new_serialized_params(params(), ctx);
    let vk = native_verifier::new_serialized_vk(vk(), circuit_info(), ctx);
    let cap = token::new_mint_cap(ctx);
    let mut store = token::register(ctx);

    token::mint(
        &cap,
        &mut store,
        &params,
        &vk,
        6,
        x"00",
    );

    cleanup(store, cap, params, vk);
}

#[test]
#[expected_failure(abort_code = token::EZeroAmount)]
fun test_mint_rejects_zero_amount_before_verifying() {
    let ctx = &mut tx_context::dummy();
    let params = serialized_params_store::new_serialized_params(params(), ctx);
    let vk = native_verifier::new_serialized_vk(vk(), circuit_info(), ctx);
    let cap = token::new_mint_cap(ctx);
    let mut store = token::register(ctx);

    token::mint(
        &cap,
        &mut store,
        &params,
        &vk,
        0,
        x"00",
    );

    cleanup(store, cap, params, vk);
}

#[test]
#[expected_failure(abort_code = token::EInvalidInput)]
fun test_range_check_rejects_invalid_bounds_before_verifying() {
    let ctx = &mut tx_context::dummy();
    let params = serialized_params_store::new_serialized_params(params(), ctx);
    let vk = native_verifier::new_serialized_vk(vk(), circuit_info(), ctx);

    token::range_check(&params, &vk, 6, 10, 1, x"00");

    serialized_params_store::destroy(params);
    native_verifier::destroy_serialized_vk(vk);
}

#[test]
#[expected_failure(abort_code = token::EIndexOutOfBounds)]
fun test_inbox_token_value_rejects_out_of_bounds_index() {
    let ctx = &mut tx_context::dummy();
    let store = token::register(ctx);

    token::inbox_token_value(&store, 0);

    token::destroy_store(store);
}

fun encrypted_zero(): u256 {
    1057098720325748203296752469094320832019875087793557438351763779692404987367u256
}

fun scalar(value: u8): vector<u8> {
    if (value == 0) {
        x"0000000000000000000000000000000000000000000000000000000000000000"
    } else if (value == 1) {
        x"0100000000000000000000000000000000000000000000000000000000000000"
    } else if (value == 2) {
        x"0200000000000000000000000000000000000000000000000000000000000000"
    } else if (value == 3) {
        x"0300000000000000000000000000000000000000000000000000000000000000"
    } else {
        x"0600000000000000000000000000000000000000000000000000000000000000"
    }
}

fun cleanup(
    store: token::Store,
    cap: token::MintCap,
    params: serialized_params_store::SerializedParams,
    vk: native_verifier::SerializedVK,
) {
    token::destroy_store(store);
    token::destroy_mint_cap(cap);
    serialized_params_store::destroy(params);
    native_verifier::destroy_serialized_vk(vk);
}

fun params(): vector<u8> {
    x"0400000042f8cfea72663b7832e47dc1fdeab56f2f1d07b729ce0a67a9f95480067c840de1800642e35c0a9fdd474e873eb42c6ceae6d8d8f43c0e035c9fbfb89bb32728303f01830dc2182d175d38ddb47e6cc2c2063b0831432043ac7994d29438082d9c8e35afccd69c2b897efd50d7ed0e62122388f41326dba4bc0d128ae0d14119"
}

fun vk(): vector<u8> {
    x"040401000000e8d6a310e68ff8ec0c23b3493ad971f39df348d914b69d900ef6bdb1a9380821a0d18c6d3fddc6df07b88dc384fed028707856b47f2ecf104a733b540541091054c1d5267ffcf0bb4847238fc935dff061a38e0c871a88849cf4d6460563c507b42083b1856a6aeb1c85d9942c94d017daa5a4ff5edfc46cf08ba1d025b0e3285adf9bf0d7ac95bb8db1cff4024ada370ee77158c0b3583d79e829e3445280057d2ddbb5c2d6dbc5f2f4d04cde7990d04398ffe4209787b59d4ca8cf3fdfca083bfafcc40b672a8f5e55f6e5b499cfb0f890dde2b36823a527c2d3eee7a1f52d935240d23b082f3a51d7891bc62a0f7af50b2ea077bf40037610850363338004203b2593d81f79267ccc50a960dd60a4ad849d0d22be1f321318a36a595f2a1542a3c0201d2e6111bb8e7e170542056c37d5e8de34633a62d5c5f1f7f3dd452b"
}

fun circuit_info(): vector<u8> {
    x"0b0c20acc86b4c84170be1ea86dfb0bf5d284c7bee72808a85412c71eeec572b2fbb0b208effc754694da2cb6df0dc36fe4a9bc7e3ec844490da918c007213c66bf786a38001b61dd63efa2807041eec04d2e53c1dcdef061216ff9f65a22d88b152b8d6559f994768be185bbb68e44116cb6d1017bab8dfe91dc3ddb28ed720139f34ea6505d4b098bb2b6a4f0d5ec7d96d3184666aaecda03d0d83cfe4fb06c7edccb9c5a22f720095cbbf541bd781e9d75cfd01d23ff3ca5674e05d85d001abce9688539e010404010000000403000000080100000000000000080100000000000000030000000001000100030a010000000001000000000a010100000001000000000a01020000000100000000010a03000000000100000000010a020000000001000000000405030000000005010000000005010100000005010200000000010c08020007080300030106030200000000"
}
