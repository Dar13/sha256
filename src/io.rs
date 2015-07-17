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

// ncurses
extern crate ncurses;
use ncurses::*;

pub fn load_file(filename:&str) -> Option<Vec<u8>>
{
    let mut file: File;
    let file_open:io::Result<File> = File::open(filename);
    match file_open
    {
        Ok(x) => file = x,
        Err(err) => { print_io_error(&err); return None; }
    };

    printw("File opened\n");

    let mut file_data: Vec<u8> = Vec::new();
    let bytes_read: usize;

    let read_result = file.read_to_end(&mut file_data);
    match read_result
    {
        Ok(x) => bytes_read = x,
        Err(err) => { print_io_error(&err); return None; }
    };

    printw("Bytes read: ");
    printw(&(bytes_read.to_string())[..]);
    printw("\n");

    return Some(file_data);
}

fn print_io_error(err: &io::Error)
{
    printw("\n");
    printw("An error has occurred performing an I/O operation.\n");
    printw("Description: ");
    printw(err.description());
    printw("\n");

    let error_os_code = err.raw_os_error();
    match error_os_code
    {
        Some(x) => { printw(&(x.to_string())[..]); printw("\n"); },
        None => { printw("No OS code available\n"); }
    }

    let error_kind:io::ErrorKind = err.kind();
    match error_kind
    {
        io::ErrorKind::NotFound => printw("File not found!"),
        io::ErrorKind::PermissionDenied => printw("Insufficient permissions!"),
        io::ErrorKind::AlreadyExists => printw("File already exists!"),
        io::ErrorKind::WouldBlock => printw("Operation would block!"),
        io::ErrorKind::TimedOut => printw("Operation timed out!"),
        io::ErrorKind::WriteZero => printw("Call to write() returned Ok(0)"),
        io::ErrorKind::Other => printw("Refer to OS code provided."),
        io::ErrorKind::Interrupted => printw("I/O operation interrupted!"),
        _ => printw("Other error occurred. Refer to print_io_error().")
    };

    printw("\n");
}
