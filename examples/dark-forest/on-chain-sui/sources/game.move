module dark_forest_sui::game;

use sui::bcs;
use verifier_api::native_verifier::{Self, SerializedCircuit, SerializedProof, SerializedVK};
use verifier_api::serialized_public_inputs;
use verifier_api::serialized_params_store::SerializedParams;

public struct Planet has copy, drop, store {
    coord_hash: u256,
    energy: u64,
    capacity: u64,
    defense: u64,
    level: u64,
    owner: Option<address>,
}

public struct Fleet has copy, drop, store {
    id: u64,
    from_planet_id: u64,
    to_planet_id: u64,
    energy: u64,
    speed: u64,
    owner: address,
}

public struct Game has key, store {
    id: UID,
    planets: vector<Planet>,
    fleets: vector<Fleet>,
    next_fleet_id: u64,
}

const EInvalidProof: u64 = 1;
const EAlreadyHasPlanet: u64 = 2;
const EInvalidTarget: u64 = 3;
const ENotOwner: u64 = 4;
const EInsufficientEnergy: u64 = 5;
const EZeroEnergy: u64 = 6;

public fun new_game(ctx: &mut TxContext): Game {
    Game {
        id: object::new(ctx),
        planets: vector[],
        fleets: vector[],
        next_fleet_id: 1,
    }
}

entry fun new_game_to_sender(ctx: &mut TxContext) {
    transfer::transfer(new_game(ctx), ctx.sender())
}

public fun create_planet(
    game: &mut Game,
    owner: address,
    params: &SerializedParams,
    vk: &SerializedVK,
    circuit: &SerializedCircuit,
    coord_hash: u256,
    proof: vector<u8>,
) {
    let mut i = 0;
    while (i < game.planets.length()) {
        let planet = &game.planets[i];
        assert!(
            !(option::is_some(&planet.owner) && *option::borrow(&planet.owner) == owner),
            EAlreadyHasPlanet,
        );
        i = i + 1;
    };

    let mut public_inputs = empty_vm_public_inputs();
    push_u256(&mut public_inputs, coord_hash);
    verify(params, vk, circuit, public_inputs, proof);

    game.planets.push_back(Planet {
        coord_hash,
        energy: 1000,
        capacity: 5000,
        defense: 100,
        level: 1,
        owner: option::some(owner),
    });
}

public fun create_planet_with_proof(
    game: &mut Game,
    owner: address,
    params: &SerializedParams,
    vk: &SerializedVK,
    circuit: &SerializedCircuit,
    coord_hash: u256,
    proof: &SerializedProof,
) {
    let mut i = 0;
    while (i < game.planets.length()) {
        let planet = &game.planets[i];
        assert!(
            !(option::is_some(&planet.owner) && *option::borrow(&planet.owner) == owner),
            EAlreadyHasPlanet,
        );
        i = i + 1;
    };

    let mut public_inputs = empty_vm_public_inputs();
    push_u256(&mut public_inputs, coord_hash);
    verify_serialized_proof(params, vk, circuit, public_inputs, proof);

    game.planets.push_back(Planet {
        coord_hash,
        energy: 1000,
        capacity: 5000,
        defense: 100,
        level: 1,
        owner: option::some(owner),
    });
}

entry fun create_planet_entry(
    game: &mut Game,
    params: &SerializedParams,
    vk: &SerializedVK,
    circuit: &SerializedCircuit,
    coord_hash: u256,
    proof: vector<u8>,
    _ctx: &mut TxContext,
) {
    create_planet(
        game,
        _ctx.sender(),
        params,
        vk,
        circuit,
        coord_hash,
        proof,
    )
}

entry fun create_planet_with_proof_entry(
    game: &mut Game,
    params: &SerializedParams,
    vk: &SerializedVK,
    circuit: &SerializedCircuit,
    coord_hash: u256,
    proof: &SerializedProof,
    _ctx: &mut TxContext,
) {
    create_planet_with_proof(
        game,
        _ctx.sender(),
        params,
        vk,
        circuit,
        coord_hash,
        proof,
    )
}

public fun max_speed_by_level(level: u64): u64 {
    if (level == 1) { 1500 }
    else if (level == 2) { 3000 }
    else if (level == 3) { 6000 }
    else if (level == 4) { 10000 }
    else if (level == 5) { 15000 }
    else if (level == 6) { 22000 }
    else if (level == 7) { 32000 }
    else if (level == 8) { 48000 }
    else if (level == 9) { 75000 }
    else { 120000 }
}

public fun dispatch_fleet(
    game: &mut Game,
    owner: address,
    from_id: u64,
    to_id: u64,
    energy: u64,
    speed: u64,
) {
    assert!(from_id > 0 && to_id > 0 && from_id != to_id, EInvalidTarget);
    assert!(from_id <= game.planets.length(), EInvalidTarget);
    assert!(to_id <= game.planets.length(), EInvalidTarget);
    assert!(energy > 0, EZeroEnergy);
    assert!(speed > 0, EInvalidTarget);

    let from = &mut game.planets[from_id - 1];
    assert!(option::is_some(&from.owner) && *option::borrow(&from.owner) == owner, ENotOwner);
    assert!(from.energy >= energy, EInsufficientEnergy);
    assert!(speed <= max_speed_by_level(from.level), EInvalidTarget);
    from.energy = from.energy - energy;

    let fleet_id = game.next_fleet_id;
    game.next_fleet_id = fleet_id + 1;
    game.fleets.push_back(Fleet {
        id: fleet_id,
        from_planet_id: from_id,
        to_planet_id: to_id,
        energy,
        speed,
        owner,
    });
}

entry fun dispatch_fleet_entry(
    game: &mut Game,
    from_id: u64,
    to_id: u64,
    energy: u64,
    speed: u64,
    _ctx: &mut TxContext,
) {
    dispatch_fleet(game, _ctx.sender(), from_id, to_id, energy, speed)
}

public fun process_arrival(
    game: &mut Game,
    params: &SerializedParams,
    vk: &SerializedVK,
    circuit: &SerializedCircuit,
    fleet_id: u64,
    distance_squared: u128,
    proof: vector<u8>,
) {
    let idx = fleet_index(game, fleet_id);
    let fleet = game.fleets[idx];
    let from_planet = game.planets[fleet.from_planet_id - 1];
    let to_planet = game.planets[fleet.to_planet_id - 1];
    let hash_1 = from_planet.coord_hash;
    let hash_2 = to_planet.coord_hash;

    let mut public_inputs = empty_vm_public_inputs();
    push_u256(&mut public_inputs, hash_1);
    push_u256(&mut public_inputs, hash_2);
    push_u128(&mut public_inputs, distance_squared);
    verify(params, vk, circuit, public_inputs, proof);

    assert!(distance_squared <= 18446744073709551615u128, EInvalidTarget);
    let energy_cost = (distance_squared as u64) / fleet.speed;

    if (energy_cost >= fleet.energy) {
        game.fleets.remove(idx);
        return
    };

    let remaining = fleet.energy - energy_cost;
    let target = &mut game.planets[fleet.to_planet_id - 1];
    if (option::is_none(&target.owner)) {
        option::fill(&mut target.owner, fleet.owner);
        target.energy = target.energy + (remaining - (remaining / 10));
    } else if (*option::borrow(&target.owner) == fleet.owner) {
        target.energy = target.energy + remaining;
        target.defense = target.defense + (remaining / 20);
    } else {
        let total_defense = target.defense + target.energy;
        if (remaining > total_defense) {
            let _old_owner = option::extract(&mut target.owner);
            option::fill(&mut target.owner, fleet.owner);
            target.energy = remaining - total_defense;
            target.defense = 100;
        }
    };

    game.fleets.remove(idx);
}

entry fun process_arrival_entry(
    game: &mut Game,
    params: &SerializedParams,
    vk: &SerializedVK,
    circuit: &SerializedCircuit,
    fleet_id: u64,
    distance_squared: u128,
    proof: vector<u8>,
) {
    process_arrival(
        game,
        params,
        vk,
        circuit,
        fleet_id,
        distance_squared,
        proof,
    )
}

public fun upgrade_planet(game: &mut Game, owner: address, planet_id: u64, cost: u64) {
    assert!(planet_id > 0 && planet_id <= game.planets.length(), EInvalidTarget);
    let planet = &mut game.planets[planet_id - 1];

    assert!(option::is_some(&planet.owner) && *option::borrow(&planet.owner) == owner, ENotOwner);
    assert!(planet.energy >= cost, EInsufficientEnergy);

    planet.energy = planet.energy - cost;
    planet.level = planet.level + 1;
    planet.capacity = planet.capacity + ((planet.level + 1) * 10);
    planet.defense = planet.defense + (planet.level * 5);
}

entry fun upgrade_planet_entry(
    game: &mut Game,
    planet_id: u64,
    cost: u64,
    _ctx: &mut TxContext,
) {
    upgrade_planet(game, _ctx.sender(), planet_id, cost)
}

public fun generate_resources(
    game: &mut Game,
    owner: address,
    planet_id: u64,
    now: u64,
    last_claim_time: u64,
) {
    assert!(planet_id > 0 && planet_id <= game.planets.length(), EInvalidTarget);
    let planet = &mut game.planets[planet_id - 1];

    assert!(option::is_some(&planet.owner) && *option::borrow(&planet.owner) == owner, ENotOwner);

    let rate = planet.level + 1;
    let elapsed = if (now > last_claim_time) { now - last_claim_time } else { 0 };
    let new_energy = rate * elapsed;

    planet.energy = if (planet.energy + new_energy > planet.capacity) {
        planet.capacity
    } else {
        planet.energy + new_energy
    };
}

entry fun generate_resources_entry(
    game: &mut Game,
    planet_id: u64,
    now: u64,
    last_claim_time: u64,
    _ctx: &mut TxContext,
) {
    generate_resources(game, _ctx.sender(), planet_id, now, last_claim_time)
}

public fun planet_count(game: &Game): u64 {
    game.planets.length()
}

public fun fleet_count(game: &Game): u64 {
    game.fleets.length()
}

public fun planet_coord_hash(game: &Game, planet_id: u64): u256 {
    game.planets[planet_id - 1].coord_hash
}

public fun planet_energy(game: &Game, planet_id: u64): u64 {
    game.planets[planet_id - 1].energy
}

public fun planet_capacity(game: &Game, planet_id: u64): u64 {
    game.planets[planet_id - 1].capacity
}

public fun planet_defense(game: &Game, planet_id: u64): u64 {
    game.planets[planet_id - 1].defense
}

public fun planet_level(game: &Game, planet_id: u64): u64 {
    game.planets[planet_id - 1].level
}

public fun planet_has_owner(game: &Game, planet_id: u64): bool {
    option::is_some(&game.planets[planet_id - 1].owner)
}

public fun planet_owner(game: &Game, planet_id: u64): address {
    *option::borrow(&game.planets[planet_id - 1].owner)
}

public fun fleet_from(game: &Game, fleet_id: u64): u64 {
    game.fleets[fleet_index(game, fleet_id)].from_planet_id
}

public fun fleet_to(game: &Game, fleet_id: u64): u64 {
    game.fleets[fleet_index(game, fleet_id)].to_planet_id
}

public fun fleet_energy(game: &Game, fleet_id: u64): u64 {
    game.fleets[fleet_index(game, fleet_id)].energy
}

public fun fleet_speed(game: &Game, fleet_id: u64): u64 {
    game.fleets[fleet_index(game, fleet_id)].speed
}

public fun fleet_owner(game: &Game, fleet_id: u64): address {
    game.fleets[fleet_index(game, fleet_id)].owner
}

public fun planet_owner_option_for_test(game: &Game, planet_id: u64): Option<address> {
    game.planets[planet_id - 1].owner
}

public fun destroy_game(game: Game) {
    let Game { id, planets: _, fleets: _, next_fleet_id: _ } = game;
    object::delete(id)
}

#[test_only]
public fun add_planet_for_test(
    game: &mut Game,
    coord_hash: u256,
    energy: u64,
    capacity: u64,
    defense: u64,
    level: u64,
    owner: address,
) {
    game.planets.push_back(Planet {
        coord_hash,
        energy,
        capacity,
        defense,
        level,
        owner: option::some(owner),
    })
}

fun fleet_index(game: &Game, fleet_id: u64): u64 {
    let mut i = 0;
    while (i < game.fleets.length()) {
        if (game.fleets[i].id == fleet_id) {
            return i
        };
        i = i + 1;
    };
    abort EInvalidTarget
}

fun verify(
    params: &SerializedParams,
    vk: &SerializedVK,
    circuit: &SerializedCircuit,
    public_inputs_bytes: vector<vector<vector<u8>>>,
    proof: vector<u8>,
) {
    assert!(
        native_verifier::verify_proof(
            params,
            vk,
            circuit,
            serialized_public_inputs::from_bytes(public_inputs_bytes),
            proof,
            native_verifier::kzg_gwc(),
            false,
            0,
        ),
        EInvalidProof,
    );
}

fun verify_serialized_proof(
    params: &SerializedParams,
    vk: &SerializedVK,
    circuit: &SerializedCircuit,
    public_inputs_bytes: vector<vector<vector<u8>>>,
    proof: &SerializedProof,
) {
    assert!(
        native_verifier::verify_serialized_proof(
            params,
            vk,
            circuit,
            serialized_public_inputs::from_bytes(public_inputs_bytes),
            proof,
            native_verifier::kzg_gwc(),
            false,
            0,
        ),
        EInvalidProof,
    );
}

fun empty_vm_public_inputs(): vector<vector<vector<u8>>> {
    vector[vector[], vector[], vector[], vector[]]
}

fun push_u128(public_inputs: &mut vector<vector<vector<u8>>>, value: u128) {
    push_vm_row(public_inputs, 0, value, 0)
}

fun push_u256(public_inputs: &mut vector<vector<vector<u8>>>, value: u256) {
    let lo_mask = (1u256 << 128) - 1;
    let lo = ((value & lo_mask) as u128);
    let hi = ((value >> 128) as u128);
    push_vm_row(public_inputs, 0, lo, hi)
}

fun push_vm_row(
    public_inputs: &mut vector<vector<vector<u8>>>,
    sub_index: u128,
    word_lo: u128,
    word_hi: u128,
) {
    public_inputs[0].push_back(scalar_u128(sub_index));
    public_inputs[1].push_back(scalar_u128(0));
    public_inputs[2].push_back(scalar_u128(word_lo));
    public_inputs[3].push_back(scalar_u128(word_hi));
}

fun scalar_u128(value: u128): vector<u8> {
    let mut bytes = bcs::to_bytes(&value);
    let mut i = 0;
    while (i < 16u64) {
        bytes.push_back(0);
        i = i + 1;
    };
    bytes
}

#[test_only]
public fun coord_public_inputs_for_test(coord_hash: u256): vector<vector<vector<u8>>> {
    let mut public_inputs = empty_vm_public_inputs();
    push_u256(&mut public_inputs, coord_hash);
    public_inputs
}

#[test_only]
public fun distance_public_inputs_for_test(
    hash_1: u256,
    hash_2: u256,
    distance_squared: u128,
): vector<vector<vector<u8>>> {
    let mut public_inputs = empty_vm_public_inputs();
    push_u256(&mut public_inputs, hash_1);
    push_u256(&mut public_inputs, hash_2);
    push_u128(&mut public_inputs, distance_squared);
    public_inputs
}
