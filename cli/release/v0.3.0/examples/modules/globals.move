address 0x1 {
module Globals {
    struct G has key, store {
        value: u64,
    }
    struct GG has key, store {
        value: u64,
        g: G
    }


    public fun new_g(account: &signer, value: u64) {
        move_to(account, G { value });
    }
    public fun read_g(addr: address): u64 acquires G {
        let g = borrow_global<G>(addr);
        g.value
    }
    public fun write_g(addr: address, new_value: u64) acquires G {
        let g = borrow_global_mut<G>(addr);
        g.value = new_value
    }

    public fun new_gg(account: &signer, v1: u64, v2: u64){
        move_to(account, GG { value: v1, g: G{ value: v2 }})
    }
    public fun read_gg(addr: address): (u64, u64) acquires GG {
        let gg = borrow_global<GG>(addr);
        (gg.value, gg.g.value)
    }

    public fun write_gg(addr: address, v1: u64, v2: u64) acquires GG {
        let gg = borrow_global_mut<GG>(addr);
        gg.value = v1;
        gg.g.value = v2;
    }
}
}