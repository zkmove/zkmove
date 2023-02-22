address 0x1 {
module Globals {
    struct G has key, store {
        value: u64,
    }
/*     struct GG has key, store {
        value: u64,
        g: G
    }
 */

    public fun new_g(account: &signer, value: u64) {
        move_to(account, G { value });
    }
    public fun borrow_g(addr: address) acquires G {
        let _ = borrow_global<G>(addr);
    }
    public fun borrow_mut_g(addr: address) acquires G {
        let _ = borrow_global_mut<G>(addr);
    }
}
}