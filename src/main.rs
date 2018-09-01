#![feature(duration_as_u128)]
#[macro_use]
extern crate failure;
extern crate bcc;
use bcc::core::BPF;
extern crate libc;
extern crate shiplift;
extern crate tera;
use failure::Error;
#[macro_use]
extern crate serde_json;
use bcc::perf::init_perf_map;
use std::cell::RefCell;
use std::io::prelude::*;
use std::io::stdout;
use std::ptr;
use std::rc::Rc;
use std::sync::mpsc;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::Once;
use std::{io, thread, time};
#[macro_use]
extern crate prettytable;
use libc::uint32_t;
use prettytable::cell::Cell;
use prettytable::row::Row;
use prettytable::Table;
use std::ffi::CString;
use std::fs::File;
use std::mem;
use std::path::Path;
// #[derive(Debug)]
// enum ParsedDataType {
//     KMALLOC,
//     KFREE,
//     RUNTIME,
//     BLKIO,
//     NETIO,
//     PAGEFREE,
//     PAGEALLOC,
// }

// enum ParsedData {
//     Kmalloc(kmalloc_data),
//     Kfree(kmalloc_data),
//     CpuRuntime(cpu_runtime),
//     BlkIo(blk_io_data),
//     NetIo(net_io_data),
//     PageFree(page_data),
//     PageAlloc(page_data),
// }

mod container;
mod helper;
// fn do_backgroud_bpf(
//     bpf_code: String,
//     parsed_data_sender: Sender<ParsedData>,
// ) -> Result<Vec<thread::JoinHandle<()>>, Error> {
//     let mut module = BPF::new(&bpf_code)?;
//     let sched_stat_runtime_collector = module.load_tracepoint("sched_stat_runtime_collector")?;
//     let blk_io_collector = module.load_kprobe("blk_io_collector")?;
//     let send_to_tracepoint = module.load_tracepoint("send_to_tracepoint")?;
//     let send_msg_tracepoint = module.load_tracepoint("send_msg_tracepoint")?;
//     let recv_from_tracepoint = module.load_tracepoint("recv_from_tracepoint")?;
//     let recv_msg_tracepoint = module.load_tracepoint("recv_msg_tracepoint")?;
//     module.attach_tracepoint("syscalls", "sys_enter_sendto", send_to_tracepoint)?;
//     module.attach_tracepoint("syscalls", "sys_enter_sendmsg", send_msg_tracepoint)?;
//     module.attach_tracepoint("syscalls", "sys_enter_recvfrom", recv_from_tracepoint)?;
//     module.attach_tracepoint("syscalls", "sys_enter_recvmsg", recv_msg_tracepoint)?;
//     module.attach_tracepoint("sched", "sched_stat_runtime", sched_stat_runtime_collector)?;
//     module.attach_kprobe("blk_account_io_completion", blk_io_collector)?;
//     let cpu_runtime_event = module.table("cpu_runtime_event");
//     let blk_io_event = module.table("blk_io_event");
//     let net_io_event = module.table("net_io_event");
//     let mut handlers = Vec::new();
//     let clonned_sender = parsed_data_sender.clone();
//     let mut cpu_runtime_perfmap = init_perf_map(
//         cpu_runtime_event,
//         perf_callback(clonned_sender, Arc::new(ParsedDataType::RUNTIME)),
//     )?;
//     let handler = thread::spawn(move || loop {
//         cpu_runtime_perfmap.poll(200);
//     });
//     handlers.push(handler);
//     let clonned_sender = parsed_data_sender.clone();
//     let mut blk_perf_map = init_perf_map(
//         blk_io_event,
//         perf_callback(clonned_sender, Arc::new(ParsedDataType::BLKIO)),
//     )?;
//     let handler = thread::spawn(move || loop {
//         blk_perf_map.poll(200);
//     });
//     handlers.push(handler);
//     let clonned_sender = parsed_data_sender.clone();
//     let mut net_perf_map = init_perf_map(
//         net_io_event,
//         perf_callback(clonned_sender, Arc::new(ParsedDataType::NETIO)),
//     )?;
//     let handler = thread::spawn(move || loop {
//         net_perf_map.poll(200);
//     });
//     handlers.push(handler);
//     Ok(handlers)
// }
// #[repr(C)]
// struct kmalloc_data {
//     pid: u32,
//     byte_alloc: u64,
// }
// #[repr(C)]
// struct cpu_runtime {
//     pid: u32,
//     runtime: u64,
//     vm_rss: u64,
// }
// #[repr(C)]
// struct net_io_data {
//     pid: u32,
//     request_byte: u64,
// }

// fn parse_net_io_data(x: &[u8]) -> net_io_data {
//     unsafe { ptr::read(x.as_ptr() as *const net_io_data) }
// }
// // use generic for code reusability
// fn parse_cpu_runtime(x: &[u8]) -> cpu_runtime {
//     unsafe { ptr::read(x.as_ptr() as *const cpu_runtime) }
// }

// fn parse_struct(x: &[u8]) -> kmalloc_data {
//     let data = unsafe { ptr::read(x.as_ptr() as *const kmalloc_data) };
//     data
// }

// #[repr(C)]
// struct blk_io_data {
//     pid: u32,
//     request_bytes: u64,
// }

// fn parse_blk_io(x: &[u8]) -> blk_io_data {
//     unsafe { ptr::read(x.as_ptr() as *const blk_io_data) }
// }

// #[repr(C)]
// struct page_data {
//     pid: u32,
// }

// fn parse_page_data(x: &[u8]) -> page_data {
//     unsafe { ptr::read(x.as_ptr() as *const page_data) }
// }

// fn perf_callback(
//     sender: Sender<ParsedData>,
//     parse_type: Arc<ParsedDataType>,
// ) -> Box<Fn() -> Box<FnMut(&[u8]) + Send>> {
//     Box::new(move || -> Box<FnMut(&[u8]) + Send> {
//         let sender = sender.clone();
//         let parse_type = Arc::clone(&parse_type);
//         return Box::new(move |x| {
//             match *parse_type {
//                 ParsedDataType::KMALLOC => {
//                     sender.send(ParsedData::Kmalloc(parse_struct(x))).unwrap();
//                 }
//                 ParsedDataType::KFREE => {
//                     sender.send(ParsedData::Kfree(parse_struct(x))).unwrap();
//                 }
//                 ParsedDataType::RUNTIME => {
//                     sender
//                         .send(ParsedData::CpuRuntime(parse_cpu_runtime(x)))
//                         .unwrap();
//                 }
//                 ParsedDataType::BLKIO => {
//                     sender.send(ParsedData::BlkIo(parse_blk_io(x))).unwrap();
//                 }
//                 ParsedDataType::NETIO => {
//                     sender
//                         .send(ParsedData::NetIo(parse_net_io_data(x)))
//                         .unwrap();
//                 }
//                 ParsedDataType::PAGEFREE => sender
//                     .send(ParsedData::PageFree(parse_page_data(x)))
//                     .unwrap(),
//                 ParsedDataType::PAGEALLOC => sender
//                     .send(ParsedData::PageAlloc(parse_page_data(x)))
//                     .unwrap(),
//             };
//         });
//     })
// }

// fn main() {
//     let mut containers =
//         container::ContainerDetails::default().expect("unable to colllect containers");
//     let (parsed_data_sender, parsed_data_reciver): (Sender<ParsedData>, Receiver<ParsedData>) =
//         mpsc::channel();
//     let bpf_code = container::get_kmalloc_kfree_bpf(&containers).expect("unable to create bpf");
//     for i in 0..containers.len() {
//         // let size = match containers[i].get_mem() {
//         //     Ok(size) => size,
//         //     Err(x) => panic!(x),
//         // };
//         // containers[i].set_mem(size);
//         for pid_index in 0..containers[i].pids.len() {
//             let runtime = match containers[i].get_cpu_runtime(&containers[i].pids[pid_index]) {
//                 Ok(runtime) => runtime,
//                 Err(x) => panic!(x),
//             };
//             let pid = containers[i].pids[pid_index].clone();
//             containers[i].set_cpu_runtime(pid, time::Duration::from_secs(runtime as u64));
//         }
//     }
//     let mut handlers =
//         do_backgroud_bpf(bpf_code, parsed_data_sender).expect("unable to get handler");
//     let containers = Arc::new(Mutex::new(containers));
//     let clonned_containers = containers.clone();
//     let handler = thread::spawn(move || loop {
//         if let Ok(msg) = parsed_data_reciver.recv() {
//             {
//                 match msg {
//                     ParsedData::Kmalloc(msg) => {
//                         // let mut containers = clonned_containers.lock().unwrap();
//                         // for i in 0..containers.len() {
//                         //     if containers[i].pids.contains(&msg.pid.to_string()) {
//                         //         containers[i].memory += msg.byte_alloc as i32;
//                         //     }
//                         // }
//                     }
//                     ParsedData::Kfree(msg) => {
//                         // let mut containers = clonned_containers.lock().unwrap();
//                         // for i in 0..containers.len() {
//                         //     if containers[i].pids.contains(&msg.pid.to_string()) {
//                         //         containers[i].memory -= msg.byte_alloc as i32;
//                         //     }
//                         // }
//                     }
//                     ParsedData::CpuRuntime(msg) => {
//                         let mut containers = clonned_containers.lock().unwrap();
//                         for i in 0..containers.len() {
//                             if containers[i].pids.contains(&msg.pid.to_string()) {
//                                 containers[i]
//                                     .add_cpu_runtime(msg.pid.to_string(), msg.runtime as f64);
//                                 containers[i].set_mem(msg.pid.to_string(), msg.vm_rss);
//                             }
//                         }
//                     }
//                     ParsedData::BlkIo(msg) => {
//                         let mut containers = clonned_containers.lock().unwrap();
//                         for i in 0..containers.len() {
//                             if containers[i].pids.contains(&msg.pid.to_string()) {
//                                 containers[i].blk_io = msg.request_bytes;
//                             }
//                         }
//                     }
//                     ParsedData::NetIo(msg) => {
//                         println!("{}", "yo");
//                         let mut containers = clonned_containers.lock().unwrap();
//                         for i in 0..containers.len() {
//                             if containers[i].pids.contains(&msg.pid.to_string()) {
//                                 containers[i].net_io = msg.request_byte;
//                             }
//                         }
//                     }
//                     ParsedData::PageAlloc(msg) => {
//                         // let mut containers = clonned_containers.lock().unwrap();
//                         // for i in 0..containers.len() {
//                         //     if containers[i].pids.contains(&msg.pid.to_string()) {
//                         //         containers[i].memory += 4;
//                         //     }
//                         // }
//                     }
//                     ParsedData::PageFree(msg) => {
//                         // let mut containers = clonned_containers.lock().unwrap();
//                         // for i in 0..containers.len() {
//                         //     if containers[i].pids.contains(&msg.pid.to_string()) {
//                         //         containers[i].memory += 4;
//                         //     }
//                         // }
//                     }
//                 }
//             }
//         }
//     });
//     handlers.push(handler);
//     let clonned_containers = containers.clone();
//     let handler = thread::spawn(move || loop {
//         {
//             let mut containers = clonned_containers.lock().unwrap();
//             let mut table = Table::new();
//             table.add_row(row![
//                 "container name",
//                 "memory",
//                 "cpu",
//                 "block io",
//                 "net_io"
//             ]);
//             for i in 0..containers.len() {
//                 let blk_io = &containers[i].blk_io.clone();
//                 let net_io = &containers[i].net_io.clone();
//                 containers[i].blk_io = 0;
//                 let name = &containers[i].name;
//                 let memory = containers[i].get_vm_rss();
//                 let mut cpu_usage = 0.00;
//                 for pid in &containers[i].pids {
//                     let usedcputime = containers[i].usedcputime.get(pid).expect("unable to get");
// let diff = container::get_uptime() as f64
//     - (container::start_time_for_pid(pid.parse().expect("unable to parse"))
//         as f64 / container::tick_to_second() as f64);
//                     let usage_for_pid = (usedcputime.as_secs() as f64 / diff) * 100.0;
//                     cpu_usage += usage_for_pid;
//                 }
//                 if cpu_usage as i32 == 0 {
//                     cpu_usage = 0.1;
//                 }
//                 table.add_row(row![name, memory / 1024, cpu_usage, blk_io, net_io]);
//             }
//             table.printstd();

//
//         }
//         thread::sleep(time::Duration::from_millis(300));
//     });
//     handlers.push(handler);
//     for handle in handlers {
//         handle.join().unwrap();
//     }
// }

#[repr(C)]
struct sched_data {
    rss: u64,
    runtime: f64,
    start_time: f64,
}
#[repr(C)]
struct vakiyam<'a> {
    data: &'a [u8],
}

fn get_vakiyam<'a>(data: &'a String) -> vakiyam<'a> {
    vakiyam {
        data: data.as_bytes(),
    }
}

fn parse<T>(data: &[u8]) -> T {
    unsafe { ptr::read(data.as_ptr() as *const T) }
}
fn parse_uint32(data: &[u8]) -> u32 {
    unsafe { ptr::read(data.as_ptr() as *const uint32_t) }
}

fn parse_sched_data(data: &[u8]) -> sched_data {
    unsafe { ptr::read(data.as_ptr() as *const sched_data) }
}

fn do_main() -> Result<(), Error> {
    let mut prog = String::new();
    let path = Path::new("/home/schoolboy/aarai/src/bpf.c");
    let mut f = File::open(&path)?;
    match f.read_to_string(&mut prog) {
        Err(x) => return Err(format_err!("unable to read file")),
        Ok(_f) => {}
    }
    let mut module = BPF::new(&prog)?;
    let containers = container::ContainerDetails::default()?;

    // populating initial data
    let mut state_ppid = module.table("state_ppid");
    let mut state_sched = module.table("state_sched");
    let mut state_pid = module.table("state_pid");
    for i in 0..containers.len() {
        let index: uint32_t = i.clone() as u32;
        for pid in containers[i].pids.clone() {
            let c_pid: uint32_t = pid.parse::<u32>()?;
            let container_name = containers[i].name.clone();
            state_ppid.set(unsafe { helper::any_as_u8_mut_slice(&c_pid) }, unsafe {
                helper::any_as_u8_mut_slice(&index)
            })?;
            state_pid.set(unsafe { helper::any_as_u8_mut_slice(&c_pid) }, unsafe {
                helper::any_as_u8_mut_slice(&c_pid)
            })?;

            //populating the rss
            match container::get_vm_rss(pid.parse::<i32>()?) {
                Ok(rss) => {
                    let start_time = (container::start_time_for_pid(pid.parse::<i32>()?) as f64
                        / container::tick_to_second() as f64)
                        * 1000000000.0;
                    let runtime = container::get_pid_runtime(pid.parse::<i32>()?)?;
                    let data = sched_data {
                        rss: rss,
                        runtime: runtime,
                        start_time: start_time,
                    };
                    state_sched.set(unsafe { helper::any_as_u8_mut_slice(&c_pid) }, unsafe {
                        helper::any_as_u8_mut_slice(&data)
                    })?;
                }
                Err(_x) => {
                    //ignoring the missing pids , they may be gone by parsing
                    //So, I don't want to crash :P
                }
            }
        }
    }
    let sched_tracepoint = module.load_tracepoint("sched_tracepoint")?;
    module.attach_tracepoint("sched", "sched_stat_runtime", sched_tracepoint)?;

    //creating channels
    let (parsed_data_sender, parsed_data_reciver): (Sender<parse_data>, Receiver<parse_data>) =
        mpsc::channel();
    let clonned_sender = parsed_data_sender.clone();
    let state_sched_event = module.table("state_sched_event");
    let mut cpu_runtime_perfmap = init_perf_map(
        state_sched_event,
        perf_callback(clonned_sender, Arc::new(parse_data_type::Sched)),
    )?;
    let mut handlers = Vec::new();
    let handler = thread::spawn(move || loop {
        cpu_runtime_perfmap.poll(200);
    });
    handlers.push(handler);

    //reciver
    let handler = thread::spawn(move || loop {
        if let Ok(msg) = parsed_data_reciver.recv() {
            match msg {
                parse_data::Signal => {
                    ui_display(
                        &mut state_pid,
                        &mut state_ppid,
                        &mut state_sched,
                        &containers,
                    );
                }
                _ => {}
            }
        }
    });
    handlers.push(handler);
    for handle in handlers {
        handle.join().unwrap();
    }
    Ok(())
}
fn ui_display(
    state_pid: &mut bcc::table::Table,
    state_ppid: &mut bcc::table::Table,
    sched_table: &mut bcc::table::Table,
    containers: &Vec<Box<container::ContainerDetails>>,
) {
    // check pid in state_pid, get the container name,
    // add value according to that.
    let title = vec!["name", "memory"];
    let mut name = Vec::new();
    let mut memory = Vec::new();
    let mut cpu_usage = Vec::new();
    // initializing
    for i in 0..containers.len() {
        name.push(&containers[i].name);
        memory.push(0);
        cpu_usage.push(0.0);
    }
    // update the data
    for entry in sched_table.iter() {
        let key = parse_uint32(&entry.key);
        let sched_val = parse_sched_data(&entry.value);
        let ppid_val = state_pid
            .get(unsafe { helper::any_as_u8_mut_slice(&key) })
            .expect("yosop");
        let ppid = parse_uint32(&ppid_val);
        //println!("{}", ppid);
        let container_index_val = state_ppid
            .get(unsafe { helper::any_as_u8_mut_slice(&ppid) })
            .expect("poda dei");
        let container_index = parse_uint32(&container_index_val);
        let diff = container::get_uptime() as f64 - sched_val.start_time;
        memory[container_index as usize] += sched_val.rss;
        cpu_usage[container_index as usize] += sched_val.runtime / diff;
        // println!("{}", sched_val.start_time);
    }
    println!("{} {} {}", name[0], memory[0] / 1024, cpu_usage[0]);
    //print!("{}[2J", 27 as char);
}
enum parse_data {
    Sched(sched_data),
    Signal,
}
enum parse_data_type {
    Sched,
}
fn perf_callback(
    sender: Sender<parse_data>,
    parse_type: Arc<parse_data_type>,
) -> Box<Fn() -> Box<FnMut(&[u8]) + Send>> {
    Box::new(move || -> Box<FnMut(&[u8]) + Send> {
        let sender = sender.clone();
        let parse_type = Arc::clone(&parse_type);
        return Box::new(move |x| {
            match *parse_type {
                parse_data_type::Sched => {
                    sender.send(parse_data::Signal).expect("unable to send 1");
                }
            };
        });
    })
}

fn main() {
    do_main().unwrap();
}

fn get_string(x: &[u8]) -> String {
    // match x.iter().position(|&r| r == 0) {
    //     Some(zero_pos) => String::from_utf8_lossy(&x[0..zero_pos]).to_string(),
    //     None => String::from_utf8_lossy(x).to_string(),
    // }
    unsafe {
        CString::from_vec_unchecked(x.to_vec())
            .into_string()
            .expect("unable to parse name")
    }
}
