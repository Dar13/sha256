/*
 *
 *
 *
 */

use std::num::*;

pub static SHA256_CONSTS:[u32; 64] = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2];

struct fipsU32 {
    value: u64
}

impl fipsU32 {
    fn value(&self) -> u32 {
        self.value as u32
    }

    fn add(&mut self, other:u32) -> &mut fipsU32 {
        self.value = self.value + other as u64;
        self.value = self.value % 2u64.pow(32);
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
    // SHA-256 spec says the message should be in form:
    // msg + 1 + 0^k = 448 % 512

    // Final message composition:
    // msg + 1 + 0^k + (msg.len().to_binary() as u64)
    let msg_len: u64 = (data.len() as u64) * 8;
    let mut num_zeroes: u64 = (448 % 512) - (1 + msg_len);
    let first_pad: u8;

    if num_zeroes >= 7
    {
        first_pad = 0x80;
        num_zeroes = num_zeroes - 7;
        data.push(first_pad);
    }
    else
    {
        // Has to be OR'd with the size in a specific way.
        // TODO: Implement this, or enforce that the length
        //       of this message in bits is a multiple of 8.
        println!("Implement missing functionality in pad_message!");
    }

    let mut zero_bytes: u32 = 0;
    while num_zeroes > 0
    {
        data.push(0);
        zero_bytes = zero_bytes + 1;
        num_zeroes = num_zeroes - 8;
    }

    let len_binary: u64 = msg_len as u64;
    for i in 0 .. 8
    {
        data.push((len_binary >> ((7 - i) * 8)) as u8);
    }

    // Debugging output.
    let mut line_count: u32 = 0;
    let mut word_count: u32 = 0;
    for byte in data
    {
        print!("{:02X} ", byte);
        word_count = word_count + 1;
        line_count = line_count + 1;
        if line_count > 7
        {
            line_count = 0;
            println!();
        }
    }
    println!("{} bytes\n", word_count);
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
    for block_idx in 0 .. num_blocks
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

        print!("Setting up Message Scheduler\n");

        for t in 0 .. 16
        {
            match block
            {
                Some(x) => message_sched[t] = x[t],
                None => { print!("Block is invalid!\n");
                          return None; }
            };
            println!("Schedule {:02}: {:08x}", t, message_sched[t]);
        }

        for t in 16 .. 64
        {
            // Specification says that addition is performed modulo 32.
            // Isn't that just equivalent of wrapping?
            let s0 = lower_sigma_0(message_sched[t - 15]);
            let s1 = lower_sigma_1(message_sched[t - 2]);

            let mut word:fipsU32 = fipsU32{ value: 0u64 };
            word.add(message_sched[t-16]).add(s0).add(message_sched[t-7]).add(s1);

            message_sched[t] = word.value();
            println!("{:02}: {:08x}", t, message_sched[t]);
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

        println!("Initial: {:08x} {:08x} {:08x} {:08x} {:08x} {:08x} {:08x} {:08x}",
                 a, b, c, d, e, f, g, h);

        for t in 0 .. 64
        {
            let mut t1:u32 = h;
            t1 = t1.wrapping_add(upper_sigma_1(e));
            t1 = t1.wrapping_add(ch(e,f,g));
            t1 = t1.wrapping_add(SHA256_CONSTS[t]);
            t1 = t1.wrapping_add(message_sched[t]);

            let mut test_t1:fipsU32 = fipsU32{ value: h as u64 };
            test_t1.add(upper_sigma_1(e));
            test_t1.add(ch(e,f,g));
            test_t1.add(SHA256_CONSTS[t]);
            test_t1.add(message_sched[t]);

            let mut t2:u32 = upper_sigma_0(a);
            t2 = t2.wrapping_add(maj(a,b,c));

            let mut test_t2:fipsU32 = fipsU32{ value: upper_sigma_0(a) as u64 };
            test_t2.add(maj(a,b,c));

            println!("t1 = {:08x}, k[i] = {:08x}", t1, SHA256_CONSTS[t]);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);

            println!("{:02}: {:08x} {:08x} {:08x} {:08x} {:08x} {:08x} {:08x} {:08x}",
                     t, a, b, c, d, e, f, g, h);
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

        for tmp in 0 .. 8
        {
            //print!("{}\n",&(hash_value[tmp].to_string())[..]);
            print!("{:08x} ",hash_value[tmp]);
        }
        println!();

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

fn rotate_left(x:u32, amt:u32) -> u32
{
    return x.rotate_left(amt);
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
