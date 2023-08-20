//! args: 1u16, 11u32, 2u64,
script {
    fun main(x1: u16, x2: u32, y: u64) {
        // u16 test case
        // add operation
        let x = x1 + 20u16;
        // cast operation
        let y = x - (y as u16);
        // multiple operation
        let z = y * 2u16;
        // divide operation
        let z = z / 3u16;
        // modulo operation
        let w = z % 2u16; 

        // u32 test case
        // add operation
        let x = x2 + 20u32;
        // cast operation
        let y = x - (y as u32);
        // multiple operation
        let z = y * 2u32;
        // divide operation
        let z = z / 3u32;
        // modulo operation
        let w = z % 2u32; 
    }
}