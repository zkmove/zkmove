module dark_forest::game {
    use std::signer;
    use std::vector;
    use std::option::{Self, Option};
    use dark_forest::off_chain;
    use verifier_api::verifier_api;

    // ======================
    // Error codes
    // ======================
    const E_INVALID_COORDINATES: u64 = 0;
    const E_INSUFFICIENT_ENERGY: u64 = 1;
    const E_NOT_OWNER: u64 = 2;
    const E_FLEET_IN_TRANSIT: u64 = 3;
    const E_INVALID_TARGET: u64 = 4;
    const E_BATTLE_FAILURE: u64 = 5;
    const E_ALREADY_HAS_PLANET: u64 = 8;

    // ======================
    // Data structures
    // ======================
    struct Planet has copy, drop, store {
        coord_hash: u256, // hash(x, y)
        energy: u64,
        capacity: u64,
        defense: u64,
        level: u64,
        owner: Option<address>,
    }

    struct Fleet has copy, drop, store {
        from_planet_id: u64,
        to_planet_id: u64,
        energy: u64,
        speed: u64,
        owner: address,
    }

    struct GameManager has key {
        planets: vector<Planet>,
        fleets: vector<Fleet>,
        next_planet_id: u64,
        next_fleet_id: u64,
    }

    // ======================
    // Module initialization
    // ======================
    fun init_module(deployer: &signer) {
        let addr = signer::address_of(deployer);
        assert!(addr == @dark_forest, 999);
        move_to(deployer, GameManager {
            planets: vector::empty(),
            fleets: vector::empty(),
            next_planet_id: 1,
            next_fleet_id: 1,
        });
    }

    // ======================
    // Create mother planet (one per player)
    // ======================
    public entry fun create_planet(
        account: &signer,
        proof: vector<u8>,
        coord_hash: u256,
        kzg_variant: u8
    ) acquires GameManager {
        let sender = signer::address_of(account);
        let manager = borrow_global_mut<GameManager>(@dark_forest);

        let i = 0;
        while (i < vector::length(&manager.planets)) {
            let p = vector::borrow(&manager.planets, i);
            if (option::is_some(&p.owner) && *option::borrow(&p.owner) == sender) {
                abort E_ALREADY_HAS_PLANET
            };
            i = i + 1;
        };

        let id = manager.next_planet_id;
        manager.next_planet_id = id + 1;

        //TODO: implement PublicInputs::new() in halo2-verifier.move
        let pi = PublicInputs::new(coord_hash);
        assert!(verifier_api::verify_proof(@param_address, @circuit_address, pi, proof, kzg_variant) == true, E_INVALID_COORDINATES);

        vector::push_back(&mut manager.planets, Planet {
            coord_hash,
            energy: 1000,
            capacity: 5000,
            defense: 100,
            level: 1,
            owner: option::some(sender),
        });
    }

    // ======================
    // Max speed allowed by planet level (balanced progression)
    // ======================
    inline fun get_max_speed_by_level(level: u64): u64 {
        if (level == 1) { 1500 }
        else if (level == 2) { 3000 }
        else if (level == 3) { 6000 }
        else if (level == 4) { 10000 }
        else if (level == 5) { 15000 }
        else if (level == 6) { 22000 }
        else if (level == 7) { 32000 }
        else if (level == 8) { 48000 }
        else if (level == 9) { 75000 }
        else { 120000 } // level 10+ : god-tier speed
    }

    // ======================
    // Dispatch fleet - speed capped by source planet level
    // ======================
    public entry fun dispatch_fleet(
        account: &signer,
        from_id: u64,
        to_id: u64,
        energy: u64,
        speed: u64,
    ) acquires GameManager {
        assert!(energy > 0 && from_id != to_id, E_INVALID_TARGET);
        assert!(speed > 0, E_INVALID_TARGET);

        let sender = signer::address_of(account);
        let manager = borrow_global_mut<GameManager>(@dark_forest);

        let _to_planet = *vector::borrow(&manager.planets, to_id - 1);
        let from = vector::borrow_mut(&mut manager.planets, from_id - 1);
        assert!(option::is_some(&from.owner) && *option::borrow(&from.owner) == sender, E_NOT_OWNER);
        assert!(from.energy >= energy, E_INSUFFICIENT_ENERGY);

        let max_allowed_speed = get_max_speed_by_level(from.level);
        assert!(speed <= max_allowed_speed, E_INVALID_TARGET);

        from.energy = from.energy - energy;

        let fleet_id = manager.next_fleet_id;
        manager.next_fleet_id = fleet_id + 1;

        vector::push_back(&mut manager.fleets, Fleet {
            from_planet_id: from_id,
            to_planet_id: to_id,
            energy,
            speed,
            owner: sender,
        });
    }

    // ======================
    // Process fleet arrival
    // ======================
    public entry fun process_arrival(
        fleet_id: u64,
        distance_squared: u128,
        proof: vector<u8>, // proof of euclidean_distance()
        kzg_variant: u8
    ) acquires GameManager {
        let manager = borrow_global_mut<GameManager>(@dark_forest);
        let idx = fleet_id - 1;
        assert!(idx < vector::length(&manager.fleets), E_INVALID_TARGET);

        let fleet = *vector::borrow(&manager.fleets, idx);
        let from_planet = *vector::borrow(&manager.planets, fleet.from_planet_id - 1);
        let to_planet   = *vector::borrow(&manager.planets, fleet.to_planet_id - 1);
        let hash_1 = from_planet.coord_hash;
        let hash_2 = to_planet.coord_hash;

        let pi = PublicInputs::new(hash_1, hash_2, distance_squared);
        assert!(verification_api::verify_proof(@param_address, @circuit_address, pi, proof, kzg_variant) == true, E_INVALID_COORDINATES);

        // Energy cost = distance_sq / speed (higher speed = less loss per distance)
        // Use integer division - any remainder is lost (harsh universe!)
        let energy_cost = if (fleet.speed == 0) { fleet.energy } else { (distance_squared as u64) / fleet.speed };

        // If not enough energy to complete journey, fleet vanishes into the void
        if (energy_cost >= fleet.energy) {
            // Fleet destroyed during travel - dark forest claims another victim
            vector::remove(&mut manager.fleets, idx);
            return
        };

        // Remaining energy upon arrival
        let remaining_energy = fleet.energy - energy_cost;

        // Now apply the remaining energy at destination
        let target = vector::borrow_mut(&mut manager.planets, fleet.to_planet_id - 1);
        let attacker = fleet.owner;

        if (option::is_none(&target.owner)) {
            // Conquer unowned planet
            option::fill(&mut target.owner, attacker);
            target.energy = target.energy + (remaining_energy / 10); // activation cost
        } else if (*option::borrow(&target.owner) == attacker) {
            // Support own planet
            target.energy = target.energy + remaining_energy;
            target.defense = target.defense + (remaining_energy / 20);
        } else {
            // Attack enemy
            let total_def = target.defense + target.energy;
            if (remaining_energy > total_def) {
                option::fill(&mut target.owner, attacker);
                target.energy = remaining_energy - total_def;
                target.defense = 100; // reset base defense
            }
            // else: attack failed, energy lost in battle
        };

        // Fleet has arrived and delivered its payload
        vector::remove(&mut manager.fleets, idx);
    }

    // ======================
    // Upgrade planet
    // ======================
    public entry fun upgrade_planet(account: &signer, planet_id: u64, cost: u64) acquires GameManager {
        let sender = signer::address_of(account);
        let manager = borrow_global_mut<GameManager>(@dark_forest);
        let p = vector::borrow_mut(&mut manager.planets, planet_id - 1);

        assert!(option::is_some(&p.owner) && *option::borrow(&p.owner) == sender, E_NOT_OWNER);
        assert!(p.energy >= cost, E_INSUFFICIENT_ENERGY);

        p.energy = p.energy - cost;
        p.level = p.level + 1;
        p.capacity = p.capacity + ((p.level + 1) * 10);
        p.defense = p.defense + (p.level * 5);
    }

    // ======================
    // Claim accumulated resources
    // ======================
    public entry fun generate_resources(
        account: &signer,
        planet_id: u64,
        now: u64,
        last_claim_time: u64
    ) acquires GameManager {
        let sender = signer::address_of(account);
        let manager = borrow_global_mut<GameManager>(@dark_forest);
        let p = vector::borrow_mut(&mut manager.planets, planet_id - 1);

        assert!(option::is_some(&p.owner) && *option::borrow(&p.owner) == sender, E_NOT_OWNER);

        let rate = p.level + 1;
        let elapsed = if (now > last_claim_time) { now - last_claim_time } else { 0 };
        let new_energy = rate * elapsed;

        p.energy = if (p.energy + new_energy > p.capacity) {
            p.capacity
        } else {
            p.energy + new_energy
        };
    }

    // ======================
    // View functions
    // ======================
    public fun get_planet(id: u64): Planet acquires GameManager {
        let manager = borrow_global<GameManager>(@dark_forest);
        *vector::borrow(&manager.planets, id - 1)
    }

    public fun get_fleet(fleet_id: u64): Fleet acquires GameManager {
        let manager = borrow_global<GameManager>(@dark_forest);
        let idx = fleet_id - 1;
        assert!(idx < vector::length(&manager.fleets), E_INVALID_TARGET);
        *vector::borrow(&manager.fleets, idx)
    }

    public fun planet_count(): u64 acquires GameManager {
        let manager = borrow_global<GameManager>(@dark_forest);
        vector::length(&manager.planets)
    }

    public fun fleet_count(): u64 acquires GameManager {
        let manager = borrow_global<GameManager>(@dark_forest);
        vector::length(&manager.fleets)
    }
}