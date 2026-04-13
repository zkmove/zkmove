#[test_only]
module dark_forest::game_tests {
    use std::signer;
    use std::option;
    use aptos_framework::account;
    use aptos_std::debug;

    use dark_forest::game::{
        init_for_test,
        create_planet,
        dispatch_fleet,
        process_arrival,
        upgrade_planet,
        generate_resources,
        get_planet,
        get_fleet,
        planet_count,
        fleet_count,
        planet_energy,
        planet_defense,
        planet_level,
        planet_capacity,
        planet_coord_hash,
        planet_owner,
        fleet_from,
        fleet_to,
        fleet_energy,
        fleet_speed,
        fleet_owner,
    };

    // Arbitrary coord hashes as stand-ins for hash(x, y).
    const HASH_A: u256 = 111111111111111111111111111111111111111u256;
    const HASH_B: u256 = 222222222222222222222222222222222222222u256;

    // kzg variant (KZG_GWC = 1).
    const KZG_GWC: u8 = 1;

    // mock_verify_proof always returns true, so any bytes work as a proof.
    const FAKE_PROOF: vector<u8> = x"deadbeef";

    // -----------------------------------------------------------------------
    // Helper: initialise the game module and create Aptos test accounts.
    // -----------------------------------------------------------------------
    fun setup(game: &signer, alice: &signer, bob: &signer) {
        account::create_account_for_test(signer::address_of(game));
        account::create_account_for_test(signer::address_of(alice));
        account::create_account_for_test(signer::address_of(bob));
        init_for_test(game);
    }

    // -----------------------------------------------------------------------
    // Test 1: create_planet — basic registration and initial state
    // -----------------------------------------------------------------------
    #[test(game = @dark_forest, alice = @0xA1, bob = @0xB2)]
    fun test_create_planet(game: &signer, alice: &signer, bob: &signer) {
        setup(game, alice, bob);

        create_planet(alice, FAKE_PROOF, HASH_A, KZG_GWC);
        create_planet(bob,   FAKE_PROOF, HASH_B, KZG_GWC);

        assert!(planet_count() == 2, 1);

        let p1 = get_planet(1);
        assert!(planet_coord_hash(&p1) == HASH_A, 2);
        assert!(planet_energy(&p1)     == 1000,   3);
        assert!(planet_capacity(&p1)   == 5000,   4);
        assert!(planet_defense(&p1)    == 100,    5);
        assert!(planet_level(&p1)      == 1,      6);
        assert!(option::contains(&planet_owner(&p1), &signer::address_of(alice)), 7);

        let p2 = get_planet(2);
        assert!(option::contains(&planet_owner(&p2), &signer::address_of(bob)), 8);

        debug::print(&b"test_create_planet: PASSED");
    }

    // -----------------------------------------------------------------------
    // Test 2: create_planet — one player cannot own two planets
    // -----------------------------------------------------------------------
    #[test(game = @dark_forest, alice = @0xA1, bob = @0xB2)]
    #[expected_failure(abort_code = 8)]  // E_ALREADY_HAS_PLANET
    fun test_create_planet_duplicate(game: &signer, alice: &signer, bob: &signer) {
        setup(game, alice, bob);
        create_planet(alice, FAKE_PROOF, HASH_A, KZG_GWC);
        create_planet(alice, FAKE_PROOF, HASH_B, KZG_GWC); // must abort
    }

    // -----------------------------------------------------------------------
    // Test 3: dispatch_fleet — fleet creation and energy deduction
    // -----------------------------------------------------------------------
    #[test(game = @dark_forest, alice = @0xA1, bob = @0xB2)]
    fun test_dispatch_fleet(game: &signer, alice: &signer, bob: &signer) {
        setup(game, alice, bob);
        create_planet(alice, FAKE_PROOF, HASH_A, KZG_GWC); // planet 1
        create_planet(bob,   FAKE_PROOF, HASH_B, KZG_GWC); // planet 2

        // Alice sends 400 energy at speed 1000 from planet 1 → planet 2.
        dispatch_fleet(alice, 1, 2, 400, 1000);

        assert!(fleet_count() == 1, 10);

        let p1 = get_planet(1);
        assert!(planet_energy(&p1) == 600, 11); // 1000 - 400

        let f = get_fleet(1);
        assert!(fleet_from(&f)   == 1,                         12);
        assert!(fleet_to(&f)     == 2,                         13);
        assert!(fleet_energy(&f) == 400,                       14);
        assert!(fleet_speed(&f)  == 1000,                      15);
        assert!(fleet_owner(&f)  == signer::address_of(alice), 16);

        debug::print(&b"test_dispatch_fleet: PASSED");
    }

    // -----------------------------------------------------------------------
    // Test 4: dispatch_fleet — insufficient energy
    // -----------------------------------------------------------------------
    #[test(game = @dark_forest, alice = @0xA1, bob = @0xB2)]
    #[expected_failure(abort_code = 1)]  // E_INSUFFICIENT_ENERGY
    fun test_dispatch_fleet_insufficient_energy(game: &signer, alice: &signer, bob: &signer) {
        setup(game, alice, bob);
        create_planet(alice, FAKE_PROOF, HASH_A, KZG_GWC);
        create_planet(bob,   FAKE_PROOF, HASH_B, KZG_GWC);
        dispatch_fleet(alice, 1, 2, 9999, 1000); // 9999 > 1000 available
    }

    // -----------------------------------------------------------------------
    // Test 5: dispatch_fleet — speed exceeds planet level cap (level 1 → max 1500)
    // -----------------------------------------------------------------------
    #[test(game = @dark_forest, alice = @0xA1, bob = @0xB2)]
    #[expected_failure(abort_code = 4)]  // E_INVALID_TARGET
    fun test_dispatch_fleet_speed_cap(game: &signer, alice: &signer, bob: &signer) {
        setup(game, alice, bob);
        create_planet(alice, FAKE_PROOF, HASH_A, KZG_GWC);
        create_planet(bob,   FAKE_PROOF, HASH_B, KZG_GWC);
        dispatch_fleet(alice, 1, 2, 100, 9999); // speed 9999 > level-1 cap 1500
    }

    // -----------------------------------------------------------------------
    // Test 6: process_arrival — attack fails (remaining energy < total defense)
    //
    // Alice sends 900 energy at speed 1000, distance_squared = 100000.
    //   energy_cost = 100000 / 1000 = 100
    //   remaining   = 900 - 100     = 800
    //   Bob's total_def = defense(100) + energy(1000) = 1100
    //   800 < 1100 → attack fails; bob keeps planet 2.
    // -----------------------------------------------------------------------
    #[test(game = @dark_forest, alice = @0xA1, bob = @0xB2)]
    fun test_process_arrival_attack_fails(game: &signer, alice: &signer, bob: &signer) {
        setup(game, alice, bob);
        create_planet(alice, FAKE_PROOF, HASH_A, KZG_GWC);
        create_planet(bob,   FAKE_PROOF, HASH_B, KZG_GWC);

        dispatch_fleet(alice, 1, 2, 900, 1000);
        process_arrival(1, 100000, FAKE_PROOF, KZG_GWC);

        assert!(fleet_count() == 0, 20);
        let p2 = get_planet(2);
        assert!(option::contains(&planet_owner(&p2), &signer::address_of(bob)), 21);
        assert!(planet_energy(&p2) == 1000, 22); // unchanged

        debug::print(&b"test_process_arrival_attack_fails: PASSED");
    }

    // -----------------------------------------------------------------------
    // Test 7: process_arrival — successful attack, planet captured
    //
    // Alice generates resources first (rate=2 at level 1, elapsed=2000 → +4000,
    // capped at 5000), then sends 1300 energy at speed 1000, distance_sq = 100000.
    //   energy_cost = 100000 / 1000 = 100
    //   remaining   = 1300 - 100    = 1200
    //   Bob's total_def = 100 + 1000 = 1100
    //   1200 > 1100 → capture! planet 2 energy = 100, defense reset to 100.
    // -----------------------------------------------------------------------
    #[test(game = @dark_forest, alice = @0xA1, bob = @0xB2)]
    fun test_process_arrival_attack_success(game: &signer, alice: &signer, bob: &signer) {
        setup(game, alice, bob);
        create_planet(alice, FAKE_PROOF, HASH_A, KZG_GWC);
        create_planet(bob,   FAKE_PROOF, HASH_B, KZG_GWC);

        generate_resources(alice, 1, 2000, 0); // energy → 5000
        assert!(planet_energy(&get_planet(1)) == 5000, 30);

        dispatch_fleet(alice, 1, 2, 1300, 1000);
        process_arrival(1, 100000, FAKE_PROOF, KZG_GWC); // distance_sq=100000, cost=100

        assert!(fleet_count() == 0, 31);
        let p2 = get_planet(2);
        assert!(option::contains(&planet_owner(&p2), &signer::address_of(alice)), 32);
        assert!(planet_energy(&p2)  == 100, 33); // 1200 - 1100
        assert!(planet_defense(&p2) == 100, 34); // reset

        debug::print(&b"test_process_arrival_attack_success: PASSED");
    }

    // -----------------------------------------------------------------------
    // Test 8: process_arrival — fleet destroyed mid-journey
    //
    // Alice sends 100 energy at speed 1000, distance_squared = 100000.
    //   energy_cost = 100000 / 1000 = 100 ≥ 100 → fleet destroyed.
    //   Planet 2 is untouched.
    // -----------------------------------------------------------------------
    #[test(game = @dark_forest, alice = @0xA1, bob = @0xB2)]
    fun test_process_arrival_fleet_destroyed(game: &signer, alice: &signer, bob: &signer) {
        setup(game, alice, bob);
        create_planet(alice, FAKE_PROOF, HASH_A, KZG_GWC);
        create_planet(bob,   FAKE_PROOF, HASH_B, KZG_GWC);

        dispatch_fleet(alice, 1, 2, 100, 1000);
        assert!(fleet_count() == 1, 40);

        process_arrival(1, 100000, FAKE_PROOF, KZG_GWC);
        assert!(fleet_count() == 0, 41);

        let p2 = get_planet(2);
        assert!(option::contains(&planet_owner(&p2), &signer::address_of(bob)), 42);
        assert!(planet_energy(&p2) == 1000, 43); // unchanged

        debug::print(&b"test_process_arrival_fleet_destroyed: PASSED");
    }

    // -----------------------------------------------------------------------
    // Test 9: process_arrival — reinforce own planet
    //
    // After capturing planet 2, alice sends 300 energy to reinforce it.
    //   distance_sq = 100000, speed = 1000 → cost = 100, remaining = 200
    //   energy  += 200      → 100 + 200 = 300
    //   defense += 200 / 20 → 100 + 10  = 110
    // -----------------------------------------------------------------------
    #[test(game = @dark_forest, alice = @0xA1, bob = @0xB2)]
    fun test_process_arrival_reinforce(game: &signer, alice: &signer, bob: &signer) {
        setup(game, alice, bob);
        create_planet(alice, FAKE_PROOF, HASH_A, KZG_GWC);
        create_planet(bob,   FAKE_PROOF, HASH_B, KZG_GWC);

        // Step 1: capture planet 2 (distance_sq=100000, cost=100, remaining=1200 > total_def=1100).
        generate_resources(alice, 1, 2000, 0);                   // energy → 5000
        dispatch_fleet(alice, 1, 2, 1300, 1000);                 // fleet_id = 1
        process_arrival(1, 100000, FAKE_PROOF, KZG_GWC);         // alice captures planet 2; p2.energy = 100

        // Step 2: reinforce planet 2 from planet 1 (distance_sq=100000, cost=100, remaining=200).
        // This fleet is assigned stable id=2 by next_fleet_id.
        dispatch_fleet(alice, 1, 2, 300, 1000);               // fleet_id = 2
        process_arrival(2, 100000, FAKE_PROOF, KZG_GWC);

        let p2 = get_planet(2);
        assert!(planet_energy(&p2)  == 300, 50); // 100 + 200
        assert!(planet_defense(&p2) == 110, 51); // 100 + 200/20

        debug::print(&b"test_process_arrival_reinforce: PASSED");
    }

    // -----------------------------------------------------------------------
    // Test 10: upgrade_planet
    //
    // Before: level=1, energy=1000, capacity=5000, defense=100
    // cost=200 → energy=800; level→2;
    //   capacity += (2+1)*10 = 30  → 5030
    //   defense  += 2*5      = 10  → 110
    // -----------------------------------------------------------------------
    #[test(game = @dark_forest, alice = @0xA1, bob = @0xB2)]
    fun test_upgrade_planet(game: &signer, alice: &signer, bob: &signer) {
        setup(game, alice, bob);
        create_planet(alice, FAKE_PROOF, HASH_A, KZG_GWC);

        upgrade_planet(alice, 1, 200);

        let p = get_planet(1);
        assert!(planet_energy(&p)   == 800,  60);
        assert!(planet_level(&p)    == 2,    61);
        assert!(planet_capacity(&p) == 5030, 62); // 5000 + (2+1)*10
        assert!(planet_defense(&p)  == 110,  63); // 100  + 2*5

        debug::print(&b"test_upgrade_planet: PASSED");
    }

    // -----------------------------------------------------------------------
    // Test 11: upgrade_planet — insufficient energy
    // -----------------------------------------------------------------------
    #[test(game = @dark_forest, alice = @0xA1, bob = @0xB2)]
    #[expected_failure(abort_code = 1)]  // E_INSUFFICIENT_ENERGY
    fun test_upgrade_planet_insufficient_energy(game: &signer, alice: &signer, bob: &signer) {
        setup(game, alice, bob);
        create_planet(alice, FAKE_PROOF, HASH_A, KZG_GWC);
        upgrade_planet(alice, 1, 9999); // 9999 > 1000
    }

    // -----------------------------------------------------------------------
    // Test 12: generate_resources — normal accumulation and capacity cap
    //
    // level=1 → rate=2
    //   call 1: elapsed=500   → new_energy=1000, total=2000 (≤ 5000)
    //   call 2: elapsed=99500 → new_energy=199000, capped at 5000
    // -----------------------------------------------------------------------
    #[test(game = @dark_forest, alice = @0xA1, bob = @0xB2)]
    fun test_generate_resources(game: &signer, alice: &signer, bob: &signer) {
        setup(game, alice, bob);
        create_planet(alice, FAKE_PROOF, HASH_A, KZG_GWC);

        generate_resources(alice, 1, 500, 0);
        assert!(planet_energy(&get_planet(1)) == 2000, 70);

        generate_resources(alice, 1, 100000, 500); // elapsed=99500
        assert!(planet_energy(&get_planet(1)) == 5000, 71);

        debug::print(&b"test_generate_resources: PASSED");
    }

    // -----------------------------------------------------------------------
    // Test 13: full flow
    //   create → generate_resources → upgrade → attack → capture → reinforce
    // -----------------------------------------------------------------------
    #[test(game = @dark_forest, alice = @0xA1, bob = @0xB2)]
    fun test_full_flow(game: &signer, alice: &signer, bob: &signer) {
        setup(game, alice, bob);

        // 1. Both players claim their home planets.
        create_planet(alice, FAKE_PROOF, HASH_A, KZG_GWC); // planet 1
        create_planet(bob,   FAKE_PROOF, HASH_B, KZG_GWC); // planet 2
        assert!(planet_count() == 2, 80);

        // 2. Alice generates resources: rate=2, elapsed=3000 → +6000, capped at 5000.
        generate_resources(alice, 1, 3000, 0);
        assert!(planet_energy(&get_planet(1)) == 5000, 81);

        // 3. Alice upgrades her planet: costs 500 energy, level=1→2.
        //    capacity = 5000 + (2+1)*10 = 5030
        //    defense  = 100  + 2*5      = 110
        //    energy   = 5000 - 500      = 4500
        upgrade_planet(alice, 1, 500);
        let p1 = get_planet(1);
        assert!(planet_level(&p1)  == 2,    82);
        assert!(planet_energy(&p1) == 4500, 83);

        // 4. Alice attacks bob's planet.
        //    planet 2: energy=1000, defense=100 → total_def=1100
        //    fleet: 1300 energy, speed=1000, distance_sq=100000 → cost=100, remaining=1200
        //    1200 > 1100 → capture! planet 2 energy=100, defense=100.
        dispatch_fleet(alice, 1, 2, 1300, 1000);     // fleet_id = 1
        assert!(fleet_count() == 1, 84);
        assert!(fleet_energy(&get_fleet(1)) == 1300, 85);

        process_arrival(1, 100000, FAKE_PROOF, KZG_GWC);
        assert!(fleet_count() == 0, 86);

        let p2 = get_planet(2);
        assert!(option::contains(&planet_owner(&p2), &signer::address_of(alice)), 87);
        assert!(planet_energy(&p2)  == 100, 88); // 1200 - 1100
        assert!(planet_defense(&p2) == 100, 89);

        // 5. Alice's home planet after dispatching 1300: 4500 - 1300 = 3200.
        assert!(planet_energy(&get_planet(1)) == 3200, 90);

        // 6. Alice reinforces her captured planet 2 (300 energy, distance_sq=100000, cost=100, remaining=200).
        // This fleet is assigned stable id=2 by next_fleet_id.
        dispatch_fleet(alice, 1, 2, 300, 1000);               // fleet_id = 2
        process_arrival(2, 100000, FAKE_PROOF, KZG_GWC);

        let p2 = get_planet(2);
        assert!(planet_energy(&p2)  == 300, 91); // 100 + 200
        assert!(planet_defense(&p2) == 110, 92); // 100 + 200/20

        debug::print(&b"test_full_flow: PASSED");
    }
}
