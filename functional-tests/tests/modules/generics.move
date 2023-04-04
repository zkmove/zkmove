address 0x1 {
module Generics {
    struct T has key, store, copy,drop {
        v: u8
    }

    struct R_T<T: key+store+copy+drop> has key, store, copy,drop {
        t: T
    }

    struct R_P<T: key+store+copy+drop> has key, store, copy,drop {
        t: T
    }

    struct TM<phantom T> has  key, store, copy, drop {
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