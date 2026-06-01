#[test_only]
module dark_forest_sui::game_sui_tests;

use dark_forest_sui::game;
use verifier_api::native_verifier;
use verifier_api::serialized_params_store;

const ALICE: address = @0xA1;
const BOB: address = @0xB2;

const HASH_A: u256 = 111111111111111111111111111111111111111u256;
const HASH_B: u256 = 222222222222222222222222222222222222222u256;

const PI_HASH_A: u256 = 1;
const PI_HASH_B: u256 = 2;

#[test]
fun test_public_inputs_are_built_from_call_arguments() {
    let zero = scalar(0);
    let one = scalar(1);
    let two = scalar(2);
    let three = scalar(3);

    assert!(
        game::coord_public_inputs_for_test(PI_HASH_A) == vector[
            vector[copy zero],
            vector[copy zero],
            vector[copy one],
            vector[copy zero],
        ],
        0,
    );

    assert!(
        game::distance_public_inputs_for_test(PI_HASH_A, PI_HASH_B, 3) == vector[
            vector[copy zero, copy zero, copy zero],
            vector[copy zero, copy zero, copy zero],
            vector[one, two, three],
            vector[copy zero, copy zero, zero],
        ],
        1,
    );
}

#[test]
fun test_create_planet() {
    let mut game = new_game();

    game::create_planet_for_test(&mut game, ALICE, HASH_A);
    game::create_planet_for_test(&mut game, BOB, HASH_B);

    assert!(game::planet_count(&game) == 2, 1);
    assert!(game::planet_coord_hash(&game, 1) == HASH_A, 2);
    assert!(game::planet_energy(&game, 1) == 1000, 3);
    assert!(game::planet_capacity(&game, 1) == 5000, 4);
    assert!(game::planet_defense(&game, 1) == 100, 5);
    assert!(game::planet_level(&game, 1) == 1, 6);
    assert!(game::planet_owner(&game, 1) == ALICE, 7);
    assert!(game::planet_owner(&game, 2) == BOB, 8);

    game::destroy_game(game);
}

#[test]
#[expected_failure(abort_code = game::EAlreadyHasPlanet)]
fun test_create_planet_duplicate() {
    let mut game = new_game();

    game::create_planet_for_test(&mut game, ALICE, HASH_A);
    game::create_planet_for_test(&mut game, ALICE, HASH_B);

    game::destroy_game(game);
}

#[test]
fun test_dispatch_fleet() {
    let mut game = two_planet_game();

    game::dispatch_fleet(&mut game, ALICE, 1, 2, 400, 1000);

    assert!(game::fleet_count(&game) == 1, 10);
    assert!(game::planet_energy(&game, 1) == 600, 11);
    assert!(game::fleet_from(&game, 1) == 1, 12);
    assert!(game::fleet_to(&game, 1) == 2, 13);
    assert!(game::fleet_energy(&game, 1) == 400, 14);
    assert!(game::fleet_speed(&game, 1) == 1000, 15);
    assert!(game::fleet_owner(&game, 1) == ALICE, 16);

    game::destroy_game(game);
}

#[test]
#[expected_failure(abort_code = game::EInsufficientEnergy)]
fun test_dispatch_fleet_insufficient_energy() {
    let mut game = two_planet_game();

    game::dispatch_fleet(&mut game, ALICE, 1, 2, 9999, 1000);

    game::destroy_game(game);
}

#[test]
#[expected_failure(abort_code = game::EInvalidTarget)]
fun test_dispatch_fleet_speed_cap() {
    let mut game = two_planet_game();

    game::dispatch_fleet(&mut game, ALICE, 1, 2, 100, 9999);

    game::destroy_game(game);
}

#[test]
#[expected_failure(abort_code = game::EZeroEnergy)]
fun test_dispatch_fleet_rejects_zero_energy() {
    let mut game = two_planet_game();

    game::dispatch_fleet(&mut game, ALICE, 1, 2, 0, 1000);

    game::destroy_game(game);
}

#[test]
fun test_process_arrival_attack_fails() {
    let mut game = two_planet_game();

    game::dispatch_fleet(&mut game, ALICE, 1, 2, 900, 1000);
    game::process_arrival_for_test(&mut game, 1, 100000);

    assert!(game::fleet_count(&game) == 0, 20);
    assert!(game::planet_owner(&game, 2) == BOB, 21);
    assert!(game::planet_energy(&game, 2) == 1000, 22);

    game::destroy_game(game);
}

#[test]
fun test_process_arrival_attack_success() {
    let mut game = two_planet_game();

    game::generate_resources(&mut game, ALICE, 1, 2000, 0);
    assert!(game::planet_energy(&game, 1) == 5000, 30);

    game::dispatch_fleet(&mut game, ALICE, 1, 2, 1300, 1000);
    game::process_arrival_for_test(&mut game, 1, 100000);

    assert!(game::fleet_count(&game) == 0, 31);
    assert!(game::planet_owner(&game, 2) == ALICE, 32);
    assert!(game::planet_energy(&game, 2) == 100, 33);
    assert!(game::planet_defense(&game, 2) == 100, 34);

    game::destroy_game(game);
}

#[test]
fun test_process_arrival_fleet_destroyed() {
    let mut game = two_planet_game();

    game::dispatch_fleet(&mut game, ALICE, 1, 2, 100, 1000);
    assert!(game::fleet_count(&game) == 1, 40);

    game::process_arrival_for_test(&mut game, 1, 100000);

    assert!(game::fleet_count(&game) == 0, 41);
    assert!(game::planet_owner(&game, 2) == BOB, 42);
    assert!(game::planet_energy(&game, 2) == 1000, 43);

    game::destroy_game(game);
}

#[test]
fun test_process_arrival_reinforce() {
    let mut game = two_planet_game();

    game::generate_resources(&mut game, ALICE, 1, 2000, 0);
    game::dispatch_fleet(&mut game, ALICE, 1, 2, 1300, 1000);
    game::process_arrival_for_test(&mut game, 1, 100000);

    game::dispatch_fleet(&mut game, ALICE, 1, 2, 300, 1000);
    game::process_arrival_for_test(&mut game, 2, 100000);

    assert!(game::planet_energy(&game, 2) == 300, 50);
    assert!(game::planet_defense(&game, 2) == 110, 51);

    game::destroy_game(game);
}

#[test]
fun test_upgrade_planet() {
    let mut game = new_game();
    game::create_planet_for_test(&mut game, ALICE, HASH_A);

    game::upgrade_planet(&mut game, ALICE, 1, 200);

    assert!(game::planet_energy(&game, 1) == 800, 60);
    assert!(game::planet_level(&game, 1) == 2, 61);
    assert!(game::planet_capacity(&game, 1) == 5030, 62);
    assert!(game::planet_defense(&game, 1) == 110, 63);

    game::destroy_game(game);
}

#[test]
#[expected_failure(abort_code = game::EInsufficientEnergy)]
fun test_upgrade_planet_insufficient_energy() {
    let mut game = new_game();
    game::create_planet_for_test(&mut game, ALICE, HASH_A);

    game::upgrade_planet(&mut game, ALICE, 1, 9999);

    game::destroy_game(game);
}

#[test]
fun test_generate_resources() {
    let mut game = new_game();
    game::create_planet_for_test(&mut game, ALICE, HASH_A);

    game::generate_resources(&mut game, ALICE, 1, 500, 0);
    assert!(game::planet_energy(&game, 1) == 2000, 70);

    game::generate_resources(&mut game, ALICE, 1, 100000, 500);
    assert!(game::planet_energy(&game, 1) == 5000, 71);

    game::destroy_game(game);
}

#[test]
fun test_full_flow() {
    let mut game = two_planet_game();

    assert!(game::planet_count(&game) == 2, 80);

    game::generate_resources(&mut game, ALICE, 1, 3000, 0);
    assert!(game::planet_energy(&game, 1) == 5000, 81);

    game::upgrade_planet(&mut game, ALICE, 1, 500);
    assert!(game::planet_level(&game, 1) == 2, 82);
    assert!(game::planet_energy(&game, 1) == 4500, 83);

    game::dispatch_fleet(&mut game, ALICE, 1, 2, 1300, 1000);
    assert!(game::fleet_count(&game) == 1, 84);
    assert!(game::fleet_energy(&game, 1) == 1300, 85);

    game::process_arrival_for_test(&mut game, 1, 100000);
    assert!(game::fleet_count(&game) == 0, 86);
    assert!(game::planet_owner(&game, 2) == ALICE, 87);
    assert!(game::planet_energy(&game, 2) == 100, 88);
    assert!(game::planet_defense(&game, 2) == 100, 89);
    assert!(game::planet_energy(&game, 1) == 3200, 90);

    game::dispatch_fleet(&mut game, ALICE, 1, 2, 300, 1000);
    game::process_arrival_for_test(&mut game, 2, 100000);

    assert!(game::planet_energy(&game, 2) == 300, 91);
    assert!(game::planet_defense(&game, 2) == 110, 92);

    game::destroy_game(game);
}

#[test]
#[expected_failure]
fun test_create_planet_rejects_invalid_proof() {
    let ctx = &mut tx_context::dummy();
    let params = serialized_params_store::new_serialized_params(params(), ctx);
    let vk = native_verifier::new_serialized_vk(vk(), ctx);
    let circuit = native_verifier::new_serialized_circuit(circuit_info(), ctx);
    let mut game = game::new_game(ctx);

    game::create_planet(&mut game, ALICE, &params, &vk, &circuit, HASH_A, x"00");

    cleanup(game, params, vk, circuit);
}

#[test]
#[expected_failure]
fun test_process_arrival_builds_public_inputs_and_rejects_invalid_proof() {
    let ctx = &mut tx_context::dummy();
    let params = serialized_params_store::new_serialized_params(params(), ctx);
    let vk = native_verifier::new_serialized_vk(vk(), ctx);
    let circuit = native_verifier::new_serialized_circuit(circuit_info(), ctx);
    let mut game = game::new_game(ctx);

    game::create_planet_for_test(&mut game, ALICE, HASH_A);
    game::create_planet_for_test(&mut game, BOB, HASH_B);
    game::dispatch_fleet(&mut game, ALICE, 1, 2, 400, 1000);
    game::process_arrival(&mut game, &params, &vk, &circuit, 1, 3, x"00");

    cleanup(game, params, vk, circuit);
}

fun new_game(): game::Game {
    let ctx = &mut tx_context::dummy();
    game::new_game(ctx)
}

fun two_planet_game(): game::Game {
    let mut game = new_game();
    game::create_planet_for_test(&mut game, ALICE, HASH_A);
    game::create_planet_for_test(&mut game, BOB, HASH_B);
    game
}

fun scalar(value: u8): vector<u8> {
    if (value == 0) {
        x"0000000000000000000000000000000000000000000000000000000000000000"
    } else if (value == 1) {
        x"0100000000000000000000000000000000000000000000000000000000000000"
    } else if (value == 2) {
        x"0200000000000000000000000000000000000000000000000000000000000000"
    } else {
        x"0300000000000000000000000000000000000000000000000000000000000000"
    }
}

fun cleanup(
    game: game::Game,
    params: serialized_params_store::SerializedParams,
    vk: native_verifier::SerializedVK,
    circuit: native_verifier::SerializedCircuit,
) {
    game::destroy_game(game);
    serialized_params_store::destroy(params);
    native_verifier::destroy_serialized_vk(vk);
    native_verifier::destroy_serialized_circuit(circuit);
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
