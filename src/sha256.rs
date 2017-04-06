/*
 *
 *
 *
 */

pub static SHA256_CONSTS:[u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
];

struct Fips_u32 {
    value: u64
}

impl Fips_u32 {
    fn new(v:u32) -> Fips_u32 {
        Fips_u32 {
            value: v as u64
        }
    }

    fn clone(&self) -> Fips_u32 {
        Fips_u32::new(self.value())
    }

    // Truncates internal 64-bit value to get 32-bit value
    fn value(&self) -> u32 {
        self.value as u32
    }

    // Enforces the FIPS 180-2 definition of integer addition.
    // Note: Not the most efficient, wrapping is probably faster
    fn add(mut self, other:u32) -> Fips_u32 {
        self.value = self.value + other as u64;
        self.value = self.value % 2u64.pow(32);
        self
    }

    fn add_other(mut self, other:Fips_u32) -> Fips_u32 {
        self = self.add(other.value());
        self
    }
}

pub fn calc_hash(mut data: &mut Vec<u8>) -> Option<Vec<u32>>
{
    print!("Padding message\n");

    pad_message(&mut data);

    print!("Parsing message\n");
    let mut message_blocks: Vec<Box<[u32; 16]>> = parse_message(&mut data);

    let hash_init_values: [u32; 8] = [ 0x6a09e667, 0xbb67ae85, 0x3c6ef372,
                                       0xa54ff53a, 0x510e527f, 0x9b05688c,
                                       0x1f83d9ab, 0x5be0cd19];

    let mut hash_value: Vec<u32> = Vec::new();
    for idx in 0 .. 8
    {
        hash_value.push(hash_init_values[idx]);
    }

    return compute_hash(&mut hash_value, &mut message_blocks);
}

/**
 *  @brief Pad the message as specified by the SHA-256 specification.
 */
fn pad_message(data: &mut Vec<u8>)
{
    // len + 1 + k === 448 mod 512
    let msg_len: u64 = (data.len() as u64) * 8; // in bits
    let tmp_len = (msg_len + 1 + 64) % 512; // (L + 1 + 64) % 512 == number of bits in the last 512-bit block

    // Check for how much space we need to pad to the final block
    if tmp_len < 512
    {
        // At least one byte is needed to be appended, since all input is byte delineated

        // Account for the appended '1' when calculating bytes to pad
        let to_pad = (512 - tmp_len + 1) / 8;

        // Assume data is byte delineated
        for i in 0 .. to_pad
        {
            if i == 0
            {
                data.push(0x80);
            }
            else
            {
                data.push(0x0);
            }
        }
    }
    else
    {
        // There's precisely one bit for the appended '1'...
        println!("Handle the precise case in pad_message()!");
    }

    for j in (0 .. 8).rev()
    {
        data.push((msg_len >> (j * 8)) as u8);
    }

    println!("Final message is {} bytes", data.len());
}

/**
 *  @brief Split the given message into 512-bit blocks.
 *
 *  @returns 'n' 512-bit blocks in a vector.
 */
fn parse_message(data: &mut Vec<u8>) -> Vec<Box<[u32;16]>>
{
    let num_blocks: u32 = (data.len() / 64) as u32;
    let mut blocks: Vec<Box<[u32;16]>> = Vec::new();

    // Debugging output
    print!("Number of blocks: {}\n", &(num_blocks.to_string())[..]);

    let mut byte_idx:usize = 0;
    for _ in 0 .. num_blocks
    {
        // A 512-bit block
        let mut block: Box<[u32;16]> = Box::new([0;16]);

        let mut mini_block:u32;
        for i in 0 .. 16
        {
            mini_block = 0;
            for j in (0 .. 4).rev()
            {
                mini_block = mini_block | ((data[byte_idx] as u32) << (j * 8));
                byte_idx += 1;
            }
            block[i] = mini_block;
        }

        blocks.push(block);
    }

    return blocks;
}

/**
 *  @brief Compute the SHA-256 hash message digest.
 */
fn compute_hash(hash: &mut Vec<u32>, data: &mut Vec<Box<[u32;16]>>) -> Option<Vec<u32>>
{
    let mut hash_values: Vec<Vec<u32>> = Vec::new();

    let mut initial_hash_values = Vec::new();
    initial_hash_values.clone_from(hash);

    // Initial hash value.
    hash_values.push(initial_hash_values);
    for i in 1 .. (data.len() + 1)
    {
        let mut message_sched: [u32;64] = [0;64];
        let block = data.get(i - 1);

        //print!("Setting up Message Scheduler\n");

        for t in 0 .. 16
        {
            match block
            {
                Some(x) => message_sched[t] = x[t],
                None => { print!("Block is invalid!\n");
                          return None; }
            };
            //println!("Schedule {:02}: {:08x}", t, message_sched[t]);
        }

        for t in 16 .. 64
        {
            // Specification says that addition is performed modulo 32.
            // Isn't that just equivalent of wrapping?
            let s0 = lower_sigma_0(message_sched[t - 15]);
            let s1 = lower_sigma_1(message_sched[t - 2]);

            let word = Fips_u32::new(message_sched[t-16]).add(s0).add(message_sched[t-7]).add(s1);

            message_sched[t] = word.value();
            //println!("{:02}: {:08x}", t, message_sched[t]);
        }

        let mut initial_hash: Vec<u32> = Vec::new();
        match hash_values.get(i - 1)
        {
            Some(x) => initial_hash.clone_from(x),
            None => { print!("Initial hash values missing!\n");
                      return None; }
        };
        
        let mut a:u32 = initial_hash[0];
        let mut b:u32 = initial_hash[1];
        let mut c:u32 = initial_hash[2];
        let mut d:u32 = initial_hash[3];
        let mut e:u32 = initial_hash[4];
        let mut f:u32 = initial_hash[5];
        let mut g:u32 = initial_hash[6];
        let mut h:u32 = initial_hash[7];

        //println!("Initial: {:08x} {:08x} {:08x} {:08x} {:08x} {:08x} {:08x} {:08x}",
        //         a, b, c, d, e, f, g, h);

        for t in 0 .. 64
        {
            let t1:Fips_u32 = Fips_u32::new(h).add(upper_sigma_1(e))
                                              .add(ch(e,f,g))
                                              .add(SHA256_CONSTS[t])
                                              .add(message_sched[t]);

            let t2:Fips_u32 = Fips_u32::new(0u32).add(upper_sigma_0(a))
                                                 .add(maj(a,b,c));

            //println!("t1 = {:08x}, t2 = {:08x}", t1.value(), t2.value());

            h = g;
            g = f;
            f = e;
            e = t1.clone().add(d).value();
            d = c;
            c = b;
            b = a;
            a = t1.clone().add_other(t2).value();

            //println!("{:02}: {:08x} {:08x} {:08x} {:08x} {:08x} {:08x} {:08x} {:08x}",
            //         t, a, b, c, d, e, f, g, h);
        }

        let mut hash_value: Vec<u32> = Vec::new();
        hash_value.push(a.wrapping_add(initial_hash[0]));
        hash_value.push(b.wrapping_add(initial_hash[1]));
        hash_value.push(c.wrapping_add(initial_hash[2]));
        hash_value.push(d.wrapping_add(initial_hash[3]));
        hash_value.push(e.wrapping_add(initial_hash[4]));
        hash_value.push(f.wrapping_add(initial_hash[5]));
        hash_value.push(g.wrapping_add(initial_hash[6]));
        hash_value.push(h.wrapping_add(initial_hash[7]));

        /*
        for tmp in 0 .. 8
        {
            print!("{:08x} ",hash_value[tmp]);
        }
        println!();
        */

        hash_values.push(hash_value);
    }

    print!("SHA-256 algorithm finished\n");

    let mut final_hash: Vec<u32> = Vec::new();
    match hash_values.last()
    {
        Some(x) => final_hash.clone_from(x),
        None => { print!("Final hash value not found\n");
                  return None; }
    };

    return Some(final_hash);
}

fn ch(x:u32, y:u32, z:u32) -> u32
{
    return (x & y) ^ ((!x) & z);
}

fn maj(x:u32, y:u32, z:u32) -> u32
{
    return (x & y) ^ (x & z) ^ (y & z);
}

/**
 *  @brief Rotate right operation.
 *
 *  @details ROTR^n(x) == rotate_right(x,n)
 */
fn rotate_right(x:u32, amt:u32) -> u32
{
    // 10110011101|01111
    // rotate by 5
    // 01111|10110011101
    //let upper :u32 = x << (32 - amt);
    //let lower :u32 = x >> amt;
    //return upper | lower;
    return x.rotate_right(amt);
}

fn upper_sigma_0(x:u32) -> u32
{
    // ROTR^2(x) ^ ROTR^13(x) ^ ROTR^22(x)
    return rotate_right(x, 2) ^ rotate_right(x, 13) ^ rotate_right(x, 22);
}

fn upper_sigma_1(x:u32) -> u32
{
    // ROTR^6(x) ^ ROTR^11(x) ^ ROTR^25(x)
    return rotate_right(x, 6) ^ rotate_right(x, 11) ^ rotate_right(x, 25);
}

fn lower_sigma_0(x:u32) -> u32
{
    // ROTR^7(x) ^ ROTR^18(x) ^ SHR^3(x)
    return rotate_right(x, 7) ^ rotate_right(x, 18) ^ (x >> 3);
}

fn lower_sigma_1(x:u32) -> u32
{
    // ROTR^17(x) ^ ROTR^19(x) ^ SHR^10(x)
    return rotate_right(x, 17) ^ rotate_right(x, 19) ^ (x >> 10);
}
