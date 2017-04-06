/*
 *
 *
 *
 *
 */

// Project modules
mod io;
mod sha256;

// Standard library
use std::io::stdin;
use std::env::*;

fn stdin_input() -> String
{
    let mut input = String::new();
    match stdin().read_line(&mut input) {
        Ok(n) => {
            println!("{} bytes read from STDIN", n);
            println!("Input:");
            println!("{}", input);
        }
        Err(error) => println!("Error: {}", error),
    }

    return input;
}

fn main()
{
    let mut file_data: Vec<u8>;

    let mut arg:Args = args();
    if arg.len() < 2
    {
        // Reading from stdin
        file_data = stdin_input().into_bytes();
    }
    else
    {
        let filename:String;
        // Not sure if nth is zero-based or not.
        let file_arg = arg.nth(1);
        match file_arg
        {
            Some(x) => filename = x,
            None => {
                panic!("Invalid program argument given!");
            },
        }
        println!("Loading file at {}", filename);
        let load_result = io::load_file(&filename);
        match load_result
        {
            Some(x) => file_data = x,
            None => panic!("An error has occurred!")
        };
    }

    println!("Starting SHA-256 calculations\n");

    let hash_value: Vec<u32>;

    let hash = sha256::calc_hash(&mut file_data);
    match hash
    {
        Some(x) => hash_value = x,
        None => {
            println!("Unable to calculate SHA-256 hash");
            return;
        },
    };

    println!("SHA-256 message digest:");

    for i in 0 .. 8
    {
        print!("{:08x}",hash_value[i]);
    }
    println!();
}
