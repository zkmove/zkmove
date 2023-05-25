address 0x1 {
module Generics {
    struct T has key, store, copy,drop {
        v: u8
    }

    struct G_T<T: store> has key, store {
        t: T
    }

    struct G_P<T1: store, T2: store> has key, store {
        t1: T1,
        t2: T2
    }

    struct TM<phantom T> has  key, store, copy, drop {
    }
    public fun create_gt<T: store>(signer: &signer, t: T) {
        move_to(signer, G_T{t});
    }

    public fun destroy_gt<T: store>(from: address): T acquires G_T {
       let G_T{t: t} = move_from<G_T<T>>(from);
       t
    }
    public fun set_gt<T: store+drop>(from: address, t: T) acquires G_T {
        if (exists<G_T<T>>(from)) {
            let gt = borrow_global_mut<G_T<T>>(from);
            gt.t = t;
        }
    }
    public fun get_gt<T: store+copy>(from: address):T acquires G_T {
       let gt = borrow_global<G_T<T>>(from);
       gt.t
    }

    public fun create_gp<T1: store, T2: store>(signer: &signer, t1: T1, t2: T2) {
        move_to(signer, G_P{t1,t2});
    }

    public fun destroy_gp<T1: store, T2: store>(from: address): (T1,T2) acquires G_P {
       let G_P{t1,t2} = move_from<G_P<T1, T2>>(from);
       (t1,t2)
    }

    public fun hello_generic<T: copy+drop, S: copy+drop>(v: T,s: S) {
        let _ = v;
        let _ = s;
    }
    public fun save_t_times<T: copy+drop, S: copy+drop>( v: T,s: S, times: u8) {
        save_rt<S, T>(s,v, times)
    }

    fun save_rt<T: copy+drop, S: copy+drop>(t: T,s:S, left_times: u8) {
        if (left_times == 0) {
            return
        };
        save_rp<T, S>(t, s,left_times)
    }

    fun save_rp<T: copy+drop, S: copy+drop>(t: T,s: S, left_times: u8) {
        if (left_times == 0) {
            return
        };

        save_rt<T, T>(t,t, left_times - 1);
        save_rt<S, S>(s,s, left_times - 1);
    }

}
}