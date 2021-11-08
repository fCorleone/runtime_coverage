use bincode;
use colored::Colorize;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::borrow::BorrowMut;
use std::collections::hash_map::DefaultHasher;
use std::collections::BTreeMap;
use std::env;
use std::ffi;
use std::fs::{create_dir_all, remove_file, OpenOptions};
use std::hash::{Hash, Hasher};
use std::hint::spin_loop;
use std::os::raw::c_void;
use std::path::Path;
use std::process;
use std::process::exit;
use std::ptr::{null, null_mut};
use std::slice;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::RwLock;
use std::{error::Error, thread, time};
use std::cell::Cell;

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

#[derive(Hash)]
struct Branch {
    pre: u32,
    post: u32,
}
fn my_hash<T>(obj: T) -> u64
where
    T: Hash,
{
    let mut hasher = DefaultHasher::new();
    obj.hash(&mut hasher);
    hasher.finish()
}

const MAXSIZE: usize = 1 << 26;
static mut BB_Number: AtomicU32 = AtomicU32::new(0);
static mut Branch_Number: AtomicU32 = AtomicU32::new(0);
thread_local! {
    static pre_node: Cell<u32> = Cell::new(0);
    static start_branch_cal: Cell<bool> = Cell::new(false);
}
const INIT: AtomicBool = AtomicBool::new(false);
static mut SHM: [AtomicBool; MAXSIZE] = [INIT; MAXSIZE];
static mut SHM_branch: [AtomicBool; MAXSIZE] = [INIT; MAXSIZE];

// lazy_static!{
//     static ref SHM: [RwLock<bool>; MAXSIZE] = [RwLock::new(false); MAXSIZE];
//     static ref SHM_branch: [RwLock<bool>; MAXSIZE] = [RwLock::new(false); MAXSIZE];
// }

fn mark_started() {
    start_branch_cal.with(|f| f.set(true))
}

fn is_started() -> bool {
    start_branch_cal.with(|f| f.get())
}

fn mark_pre_bb(bb: u32) {
    pre_node.with(|f| {
        f.set(bb);
    })
}

fn last_bb() -> u32 {
    pre_node.with(|f| f.get())
}

#[no_mangle]
pub extern "C" fn __sanitizer_cov_trace_pc_guard(guard: *mut u32) {
    //return;
    unsafe {
        // analyzer_print!("In trace_pc_guard, guard is {:?}, MAX is {:?} ", *guard, MAXSIZE);
        // analyzer_print!("BBNumber is {:?}, Branch_Number is {:?} ", BB_Number,Branch_Number);
        // if SHM[*guard as usize] == 0{
        //     BB_Number.fetch_add(1, Ordering::Relaxed);
        //     SHM[*guard as usize] = 1;
        // }
        // match SHM[*guard as usize].wirte()
        if let Ok(_) =
            SHM[*guard as usize].compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        {
            BB_Number.fetch_add(1, Ordering::Relaxed);
        }
      //  return;
        if !is_started() {
            mark_pre_bb(*guard as u32);
            mark_started();
        } else {
            let pre = last_bb();
            let br = Branch { pre, post: *guard };
            let idx = my_hash(br) as usize % MAXSIZE;
            if let Ok(_) =
                SHM_branch[idx].compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            {
                Branch_Number.fetch_add(1, Ordering::Relaxed);
            }
            mark_pre_bb(*guard);
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

    unsafe {
        thread::spawn(move || {
            while true {
                analyzer_print!(
                    "Hey, The number of basic blocks and branches are:{:?},{:?} ",
                    BB_Number.load(Ordering::Relaxed),
                    Branch_Number.load(Ordering::Relaxed)
                );
                thread::sleep(time::Duration::from_millis(5000));
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

    analyzer_print!(
        "start! file name: {}, len: {}, tmp:{}, start: {:?}, end: {:?}",
        file_name,
        len,
        tmp,
        start,
        end
    );
    assert_eq!(len, tmp, "{:?} {:?}", start, end);
    if len >= MAXSIZE {
        analyzer_error!(
            "on my god, COV ({}, {}) exceeds MAXSIZE {}",
            0,
            len,
            MAXSIZE
        );
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
    analyzer_print!("init finish");
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
    String::from(
        env::current_exe()
            .unwrap()
            .iter()
            .last()
            .unwrap()
            .to_str()
            .unwrap(),
    )
}

fn extract_filename_from_path(path: String) -> String {
    let x: Vec<&str> = path.split("/").collect();
    x.last().unwrap().to_string()
}
