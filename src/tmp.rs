use colored::Colorize;
use std::ptr::{null, null_mut};
use std::slice;
use std::env;
use std::ffi;
use std::borrow::BorrowMut;
use std::os::raw::c_void;
use std::process;
use std::path::Path;
use std::fs::{remove_file, create_dir_all, OpenOptions};
use std::sync::atomic::{AtomicBool, Ordering};
use std::collections::BTreeMap;
use serde::{Serialize, Deserialize};
use std::hint::spin_loop;
use std::process::exit;
use std::{error::Error, thread,time};
use bincode;
use lazy_static::lazy_static;

#[macro_export]
macro_rules! analyzer_print {
    ($($arg:tt)*) => ({
        let pid = get_pid();
        print!("{} {}", format!("[{}]", pid).green().bold(), "[analyzer info]: ".green().bold());
        println!($($arg)*);
    });
}

#[macro_export]
macro_rules! analyzer_error {
    ($($arg:tt)*) => ({
        let pid = get_pid();
        print!("{} {}", format!("[{}]", pid).red().bold(), "[analyzer error]: ".red().bold());
        println!($($arg)*);
    });
}

const MAXSIZE: usize = 1 << 21;
static mut BB_Number: u32 = 0;
static mut pre_node: u32 = 0;
static mut start_branch_cal: u8 = 0;

static mut branch: Vec<(u32,u32)> = Vec::new();
static mut blocks: Vec<u32> = Vec::new();

lazy_static! {
    static ref SHM: Vec<u8> = vec![0_u8; MAXSIZE];
    // static ref branch: Vec<(u32,u32)> = Vec::new();
}

#[no_mangle]
pub extern "C" fn __sanitizer_cov_trace_pc_guard(guard: *mut u32) {
    unsafe {
        if SHM[*guard as usize] == 0{
            BB_Number = BB_Number + 1;
        }
        if SHM[*guard as usize] < 200{
            SHM[*guard as usize].wrapping_add(1);
        }
        if !blocks.contains(&*guard){
            blocks.push(*guard);
        }
        if start_branch_cal == 0 {
            pre_node = *guard;
            start_branch_cal = 1;
        } 
        else{
            let new_branch = (pre_node,*guard);
            if !branch.contains(&new_branch){
                branch.push(new_branch);
                pre_node = *guard;
            }
        }
    }
}
#[no_mangle]
pub extern "C" fn __sanitizer_cov_trace_pc_indir(callee: usize) {
    // not handle for now;

    // println!("%%%%%%%%%%%%%%%%%");
}

#[no_mangle]
pub extern "C" fn __sanitizer_cov_trace_pc_guard_init(start: *mut u32, end: *mut u32) {
    if start == end {
        return;
    }

    unsafe{
        thread::spawn(move || {
            while true{
                thread::sleep(time::Duration::from_millis(5000));
                analyzer_print!("The number of basic blocks and branches are:{:?},{:?} ", blocks.len(),branch.len()); 
            }
        });
    }
    let file_name = get_process_name();
    let pid = get_pid();
    let len = unsafe { end.offset_from(start) as usize };
    let mut tmp: usize = 0;
    let mut p = start;
    while p != end {
        p = unsafe { p.add(1) };
        tmp += 1;
    }

    analyzer_print!("start! file name: {}, len: {}, tmp:{}, start: {:?}, end: {:?}", file_name, len,tmp, start, end);
    assert_eq!(len, tmp, "{:?} {:?}", start, end);
    if len >= MAXSIZE {
        analyzer_error!("on my god, COV ({}, {}) exceeds MAXSIZE {}", 0,
        len, MAXSIZE);
        panic!();
    }
    let mut p = start;
    let mut off = 0;
    unsafe {
        while p != end {
            *p = off as _;
            off += 1;
            p = p.add(1);
        }
    }
    return;
}

fn get_pid() -> u64 {
    process::id() as u64
}

#[allow(unused)]
fn get_tid() -> u64 {
    (unsafe { libc::syscall(libc::SYS_gettid) }) as u64
}

fn get_process_name() -> String {
    String::from(env::current_exe().unwrap()
        .iter().last().unwrap().to_str().unwrap())
}

fn extract_filename_from_path(path: String) -> String {
    let x: Vec<&str> = path.split("/").collect();
    x.last().unwrap().to_string()
}
