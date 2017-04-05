/*
 *
 *
 *
 *
 */

use std::error::Error;
use std::io;
use std::io::Read;
use std::fs::*;

pub fn load_file(filename:&str) -> Option<Vec<u8>>
{
    let mut file: File;
    let file_open:io::Result<File> = File::open(filename);
    match file_open
    {
        Ok(x) => file = x,
        Err(err) => { print_io_error(&err); return None; }
    };

    print!("File opened\n");

    let mut file_data: Vec<u8> = Vec::new();
    let bytes_read: usize;

    let read_result = file.read_to_end(&mut file_data);
    match read_result
    {
        Ok(x) => bytes_read = x,
        Err(err) => { print_io_error(&err); return None; }
    };

    print!("Bytes read: {}\n", &(bytes_read.to_string())[..]);

    return Some(file_data);
}

fn print_io_error(err: &io::Error)
{
    print!("\n");
    print!("An error has occurred performing an I/O operation.\n");
    print!("Description: {}\n", err.description());

    let error_os_code = err.raw_os_error();
    match error_os_code
    {
        Some(x) => { print!("{}\n", &(x.to_string())[..]) },
        None => { print!("No OS code available\n"); }
    }

    let error_kind:io::ErrorKind = err.kind();
    match error_kind
    {
        io::ErrorKind::NotFound => println!("File not found!"),
        io::ErrorKind::PermissionDenied => println!("Insufficient permissions!"),
        io::ErrorKind::AlreadyExists => println!("File already exists!"),
        io::ErrorKind::WouldBlock => println!("Operation would block!"),
        io::ErrorKind::TimedOut => println!("Operation timed out!"),
        io::ErrorKind::WriteZero => println!("Call to write() returned Ok(0)"),
        io::ErrorKind::Other => println!("Refer to OS code provided."),
        io::ErrorKind::Interrupted => println!("I/O operation interrupted!"),
        _ => println!("Other error occurred. Refer to print_io_error().")
    };
}
