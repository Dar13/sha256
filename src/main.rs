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
use std::char;
use std::env::*;

// Ncurses
extern crate ncurses;
use ncurses::*;

fn input_string() -> String
{
    let mut ret_string = String::new();

    let mut running = true;

    while running
    {
        let input = wget_wch(stdscr());

        let mut ch:char;
        match input
        {
            Some(WchResult::Char(c)) => {
                let ch_result = char::from_u32(c);
                match ch_result
                {
                    Some(x) => ch = x,
                    None => ch = '\0'
                }
            }

            Some(WchResult::KeyCode(KEY_BACKSPACE)) => {
                let x:i32 = getcurx(stdscr());
                let y:i32 = getcury(stdscr());
                mv(y, x-1);
                refresh();
                delch();
                refresh();
                ret_string.pop();
                ch = '\0';
            }

            Some(WchResult::KeyCode(_)) => continue,
            None => continue
        }

        if ch == '\n'
        {
            running = false;
            continue;
        }

        if ch != '\0'
        {
            match(input)
            {
                Some(WchResult::Char(c)) => {
                    wechochar(stdscr(), c);
                    ret_string.push(ch);
                }

                Some(WchResult::KeyCode(_)) => continue,
                None => continue
            }
        }

        refresh();
    }

    return ret_string;
}

fn get_filename(reason:&str) -> String
{
    printw(reason);
    printw("\n");
    printw("Please enter a filename: ");
    let ret:String = input_string();

    printw("\n");
    printw("Sure (Y/N)? ");
    let mut retry = false;
    let mut choosing = true;
    while choosing
    {
        let input = getch();
        let ch_result = char::from_u32(input as u32);
        match ch_result
        {
            Some('Y') | Some('y') => choosing = false,
            _ => { choosing = false; retry = true; }
        }

        wechochar(stdscr(), input as u32);
        printw("\n");
    }

    if retry
    {
        return get_filename("Retrying.");
    }
    else
    {
        return ret;
    }
}

fn main()
{
    initscr();

    keypad(stdscr(), true);
    noecho();

    let mut filename:String;

    let mut arg:Args = args();
    if arg.len() < 2
    {
        filename = get_filename("No filename argument given to the program!");
    }
    else
    {
        // Not sure if nth is zero-based or not.
        let file_arg = arg.nth(1);
        match file_arg
        {
            Some(x) => filename = x,
            None => filename = get_filename("Invalid argument passed to program!")
        }
    }

    printw("Loading file @ ");
    printw(&filename[..]);
    printw("\n");

    refresh();

    let mut file_data: Vec<u8>;
    let load_result = io::load_file(&filename);
    match load_result
    {
        Some(x) => file_data = x,
        None => { printw("An error has occurred. Press any key to exit.");
                  getch();
                  endwin();
                  return; }
    };

    printw("Starting SHA-256 calculations\n");

    refresh();

    let hash_value: Vec<u32>;

    let hash = sha256::calc_hash(&mut file_data);
    match hash
    {
        Some(x) => hash_value = x,
        None => { printw("Unable to compute SHA-256 hash\n");
                  refresh();
                  getch();
                  endwin();
                  return; }
    };

    printw("Printing SHA-256 message digest\n");
    refresh();

    for i in 0 .. 8
    {
        let s = format!("{0:x}", hash_value[i]);
        printw(&(s)[..]);
    }
    printw("\n");

    refresh();

    getch();

    endwin();
}
