#![feature(duration_as_u128)]
#[macro_use]
extern crate failure;
extern crate bcc;
use bcc::core::BPF;
extern crate libc;
extern crate shiplift;
extern crate tera;
use failure::Error;
extern crate serde_json;
use bcc::perf::init_perf_map;
use std::io::prelude::*;
use std::ptr;
use std::sync::mpsc;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::Arc;
use std::thread;
#[macro_use]
extern crate prettytable;
use libc::uint32_t;

use std::fs::File;

use std::path::Path;

mod container;
mod helper;
mod ui;
fn parse<T>(data: &[u8]) -> T {
    unsafe { ptr::read(data.as_ptr() as *const T) }
}

fn do_main() -> Result<(), Error> {
    let mut prog = String::new();
    let path = Path::new("/home/schoolboy/aarai/src/bpf.c");
    let mut f = File::open(&path)?;
    match f.read_to_string(&mut prog) {
        Err(_x) => return Err(format_err!("unable to read file")),
        Ok(_f) => {}
    }
    let mut module = BPF::new(&prog)?;
    let mut containers = container::ContainerDetails::default()?;

    // populating initial data
    let mut state_ppid = module.table("state_ppid");
    let mut state_sched = module.table("state_sched");
    let mut state_pid = module.table("state_pid");
    for i in 0..containers.len() {
        let index: uint32_t = i.clone() as u32;
        for pid in containers[i].pids.clone() {
            let c_pid: uint32_t = pid.parse::<u32>()?;
            state_ppid.set(unsafe { helper::any_as_u8_mut_slice(&c_pid) }, unsafe {
                helper::any_as_u8_mut_slice(&index)
            })?;
            state_pid.set(unsafe { helper::any_as_u8_mut_slice(&c_pid) }, unsafe {
                helper::any_as_u8_mut_slice(&c_pid)
            })?;

            //populating the rss
            match container::get_vm_rss(pid.parse::<i32>()?) {
                Ok(rss) => {
                    let data = container::sched_data {
                        rss: rss,
                        pid: pid.parse::<u32>()?,
                        index: i as u32,
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

    let clone_tracepoint = module.load_tracepoint("clone_tracepoint")?;
    module.attach_tracepoint("syscalls", "sys_exit_clone", clone_tracepoint)?;

    let exit_tracepoint = module.load_tracepoint("exit_tracepoint")?;
    module.attach_tracepoint("syscalls", "sys_enter_exit", exit_tracepoint)?;

    let exit_group_tracepoint = module.load_tracepoint("exit_group_tracepoint")?;
    module.attach_tracepoint("syscalls", "sys_enter_exit_group", exit_group_tracepoint)?;
    //creating channels
    let (parsed_data_sender, parsed_data_reciver): (Sender<ParseData>, Receiver<ParseData>) =
        mpsc::channel();
    let clonned_sender = parsed_data_sender.clone();
    let state_sched_event = module.table("state_sched_event");
    let mut cpu_runtime_perfmap = init_perf_map(
        state_sched_event,
        perf_callback(clonned_sender, Arc::new(ParseDataType::Sched)),
    )?;
    let mut handlers = Vec::new();
    let handler = thread::spawn(move || loop {
        cpu_runtime_perfmap.poll(200);
    });
    handlers.push(handler);
    let exit_event = module.table("exit_event");
    let clonned_sender = parsed_data_sender.clone();
    let mut exit_event_perfmap = init_perf_map(
        exit_event,
        perf_callback(clonned_sender, Arc::new(ParseDataType::Exit)),
    )?;
    let handler = thread::spawn(move || loop {
        exit_event_perfmap.poll(200);
    });
    handlers.push(handler);
    // creating channels for UI update
    let (ui_sender, ui_reciver): (Sender<Vec<ui::UIData>>, Receiver<Vec<ui::UIData>>) =
        mpsc::channel();
    // bpf reciver
    let handler = thread::spawn(move || loop {
        if let Ok(msg) = parsed_data_reciver.recv() {
            match msg {
                ParseData::Sched(data) => {
                    if !containers[data.index as usize]
                        .pids
                        .contains(&data.pid.to_string())
                    {
                        containers[data.index as usize]
                            .pids
                            .push(data.pid.to_string());
                    }
                    containers[data.index as usize]
                        .sched_datas
                        .insert(data.pid.to_string(), data);
                }
                ParseData::Exit(data) => {
                    let pid_index = containers[data.index as usize]
                        .pids
                        .iter()
                        .position(|x| *x == data.pid.to_string())
                        .unwrap();
                    containers[data.index as usize].pids.remove(pid_index);
                    containers[data.index as usize]
                        .sched_datas
                        .remove(&(data.pid.to_string()));
                }
            }
            // why I'm updating here cuz I don't want to use any locks
            // and special pointer stuffs. Let's do it simple go way in rust. :p
            // what if no event? os won't rest.
            let mut ui_updates = Vec::new();
            for i in 0..containers.len() {
                let mut memory = 0;
                for (_key, value) in containers[i].clone().sched_datas {
                    memory += value.rss;
                }
                ui_updates.push(ui::UIData {
                    container_name: containers[i].name.clone(),
                    memory: memory as f64 / 1026 as f64,
                });
            }
            ui_sender.send(ui_updates).unwrap();
        }
    });
    handlers.push(handler);

    let handler = thread::spawn(move || {
        ui::display(ui_reciver);
    });
    handlers.push(handler);
    for handle in handlers {
        handle.join().unwrap();
    }
    Ok(())
}

enum ParseData {
    Sched(container::sched_data),
    Exit(container::exit_data),
}

enum ParseDataType {
    Sched,
    Exit,
}

fn perf_callback(
    sender: Sender<ParseData>,
    parse_type: Arc<ParseDataType>,
) -> Box<Fn() -> Box<FnMut(&[u8]) + Send>> {
    Box::new(move || -> Box<FnMut(&[u8]) + Send> {
        let sender = sender.clone();
        let parse_type = Arc::clone(&parse_type);
        return Box::new(move |x| {
            match *parse_type {
                ParseDataType::Sched => {
                    sender
                        .send(ParseData::Sched(parse::<container::sched_data>(x)))
                        .expect("unable to send sched data");
                }
                ParseDataType::Exit => {
                    sender
                        .send(ParseData::Exit(parse::<container::exit_data>(x)))
                        .expect("unable to send exit data");
                }
            };
        });
    })
}

fn main() {
    do_main().unwrap();
}
