/*
 *
 *
 *
 */

use std::num::*;

extern crate ncurses;
use ncurses::*;

pub static SHA256_CONSTS:[u32; 64] = [0x982f8a42, 0x91443771, 0xcffb0fb5,
                                      0xa5dbb5e9, 0x5bc25639, 0xf111f159,
                                      0xa4823f92, 0xd55e1cab, 0x98aa07d8,
                                      0x015b8312, 0xbe853124, 0xc37d0c55,
                                      0x745dbe72, 0xfeb1de80, 0xa706dc9b,
                                      0x74f19bc1, 0xc1699be4, 0x8647beef,
                                      0xc69dc10f, 0xcca10c24, 0x6f2ce92d,
                                      0xaa84744a, 0xdca9b95c, 0xda88f976,
                                      0x52513e98, 0x6dc631a8, 0xc82703b0,
                                      0xc77f59bf, 0xf30be0c6, 0x4791a7d5,
                                      0x5163ca06, 0x67292914, 0x850ab727,
                                      0x38211b2e, 0xfc6d2c4d, 0x130d3853,
                                      0x54730a65, 0xbb0a6a76, 0x2ec9c281,
                                      0x852c7292, 0xa1e8bfa2, 0x4b661aa8,
                                      0x708b4bc2, 0xa3516cc7, 0x19e892d1,
                                      0x240699d6, 0x85350ef4, 0x70a06a10,
                                      0x16c1a419, 0x086c371e, 0x4c774827,
                                      0xb5bcb034, 0xb30c1c39, 0x4aaad84e,
                                      0x4fca9c5b, 0xf36f2e68, 0xee828f74,
                                      0x6f63a578, 0x1478c884, 0x0802c78c,
                                      0xfaffbe90, 0xeb6c50a4, 0xf7a3f9be,
                                      0xf27871c6];

pub fn calc_hash(mut data: &mut Vec<u8>) -> Option<Vec<u32>>
{
    printw("Padding message\n");

    pad_message(&mut data);


    printw("Parsing message\n");
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

    /*
    // Debugging output.
    let mut line_count: u32 = 0;
    let mut word_count: u32 = 0;
    for byte in data
    {
        printw(&(byte.to_string())[..]);
        word_count = word_count + 1;
        printw(" ");
        line_count = line_count + 1;
        if line_count > 5
        {
            line_count = 0;
            printw("\n");
        }
    }
    */
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

    /*
    // Debugging output
    printw("Num blocks: ");
    printw(&(num_blocks.to_string())[..]);
    printw("\n");
    */

    for block_idx in 0 .. num_blocks
    {
        let mut block: Box<[u32;16]> = Box::new([0;16]);

        for byte_idx in 0 .. 16
        {
            let idx: usize = (block_idx * 64) as usize + (byte_idx as usize);
            let x:u32 = (((data[idx] as u32) << 24)        |
                         ((data[idx + 1] as u32) << 16)    |
                         ((data[idx + 2] as u32) << 8)     |
                         ((data[idx + 3] as u32) ));
            block[byte_idx] = x;
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

        for t in 0 .. 16
        {
            match block
            {
                Some(x) => message_sched[t] = x[t],
                None => { printw("Block is invalid!\n");
                          return None; }
            };
        }

        for t in 16 .. 64
        {
            // Specification says that addition is performed modulo 32.
            // Isn't that just equivalent of wrapping?
            let mut x = lower_sigma_1(message_sched[t - 2]);
            x = u32::wrapping_add(x, message_sched[t - 7]);
            x = u32::wrapping_add(x, lower_sigma_0(message_sched[t - 15]));
            x = u32::wrapping_add(x, message_sched[t -16]);
            message_sched[t] = x;
        }

        printw("Setting up Message Scheduler\n");
        refresh();

        let mut initial_hash: Vec<u32> = Vec::new();
        match hash_values.get(i - 1)
        {
            Some(x) => initial_hash.clone_from(x),
            None => { printw("Initial hash values missing!\n");
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

        for t in 0 .. 64
        {
            let mut t1:u32 = h;
            t1 = t1.wrapping_add(upper_sigma_1(e));
            t1 = t1.wrapping_add(ch(e,f,g));
            t1 = t1.wrapping_add(SHA256_CONSTS[t]);
            t1 = t1.wrapping_add(message_sched[t]);

            let mut t2:u32 = upper_sigma_0(a);
            t2 = t2.wrapping_add(maj(a,b,c));

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
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
            printw(&(hash_value[tmp].to_string())[..]);
            printw("\n");
        }
        refresh();

        hash_values.push(hash_value);
    }

    printw("SHA-256 algorithm finished\n");
    refresh();

    let mut final_hash: Vec<u32> = Vec::new();
    match hash_values.last()
    {
        Some(x) => final_hash.clone_from(x),
        None => { printw("Final hash value not found\n");
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
    return (x & y) ^ (x & z) ^ (y ^ z);
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
    let upper :u32 = x << (32 - amt);
    let lower :u32 = x >> amt;
    return upper | lower;
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
