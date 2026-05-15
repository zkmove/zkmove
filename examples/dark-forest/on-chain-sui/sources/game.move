module dark_forest_sui::game;

use halo2_common::serialized_public_inputs::PublicInputs;
use verifier_api::native_verifier::{Self, SerializedCircuit, SerializedVK};
use verifier_api::serialized_params_store::SerializedParams;

public struct Planet has copy, drop, store {
    coord_hash: u256,
    energy: u64,
    owner: address,
}

public struct Fleet has copy, drop, store {
    id: u64,
    from_planet_id: u64,
    to_planet_id: u64,
    energy: u64,
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

public fun new_game(ctx: &mut TxContext): Game {
    Game {
        id: object::new(ctx),
        planets: vector[],
        fleets: vector[],
        next_fleet_id: 1,
    }
}

public fun create_planet(
    game: &mut Game,
    owner: address,
    params: &SerializedParams,
    vk: &SerializedVK,
    circuit: &SerializedCircuit,
    coord_hash: u256,
    public_inputs: PublicInputs,
    proof: vector<u8>,
) {
    let mut i = 0;
    while (i < game.planets.length()) {
        assert!(game.planets[i].owner != owner, EAlreadyHasPlanet);
        i = i + 1;
    };

    assert!(
        native_verifier::verify_proof(
            params,
            vk,
            circuit,
            public_inputs,
            proof,
            native_verifier::kzg_gwc(),
            false,
            0,
        ),
        EInvalidProof,
    );

    game.planets.push_back(Planet {
        coord_hash,
        energy: 1000,
        owner,
    });
}

public fun dispatch_fleet(
    game: &mut Game,
    owner: address,
    from_id: u64,
    to_id: u64,
    energy: u64,
) {
    assert!(from_id > 0 && to_id > 0 && from_id != to_id, EInvalidTarget);
    assert!(from_id <= game.planets.length(), EInvalidTarget);
    assert!(to_id <= game.planets.length(), EInvalidTarget);

    let from = &mut game.planets[from_id - 1];
    assert!(from.owner == owner, ENotOwner);
    assert!(from.energy >= energy, EInsufficientEnergy);
    from.energy = from.energy - energy;

    let fleet_id = game.next_fleet_id;
    game.next_fleet_id = fleet_id + 1;
    game.fleets.push_back(Fleet {
        id: fleet_id,
        from_planet_id: from_id,
        to_planet_id: to_id,
        energy,
        owner,
    });
}

public fun process_arrival(
    game: &mut Game,
    params: &SerializedParams,
    vk: &SerializedVK,
    circuit: &SerializedCircuit,
    fleet_id: u64,
    distance_squared: u128,
    public_inputs: PublicInputs,
    proof: vector<u8>,
) {
    assert!(
        native_verifier::verify_proof(
            params,
            vk,
            circuit,
            public_inputs,
            proof,
            native_verifier::kzg_gwc(),
            false,
            0,
        ),
        EInvalidProof,
    );

    let idx = fleet_index(game, fleet_id);
    let fleet = game.fleets.remove(idx);
    let energy_cost = (distance_squared as u64) / 1000;
    let remaining = if (energy_cost >= fleet.energy) { 0 } else { fleet.energy - energy_cost };
    let target = &mut game.planets[fleet.to_planet_id - 1];
    target.owner = fleet.owner;
    target.energy = target.energy + remaining;
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

public fun planet_owner(game: &Game, planet_id: u64): address {
    game.planets[planet_id - 1].owner
}

public fun destroy_game(game: Game) {
    let Game { id, planets: _, fleets: _, next_fleet_id: _ } = game;
    object::delete(id)
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
