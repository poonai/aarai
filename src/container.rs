use container::libc::sysconf;
use container::libc::_SC_CLK_TCK;
use failure::Error;
use shiplift::Docker;
extern crate procinfo;
use std::collections::HashMap;
use std::fs::File;
use std::path::Path;

use std::time;
extern crate handlebars;
extern crate libc;

use std::io::Read;
#[derive(Debug, Clone)]
pub struct ContainerDetails {
    pub name: String,
    pub id: String,
    pub pids: Vec<String>,
    pub memory: HashMap<String, u64>,
    pub usedcputime: HashMap<String, time::Duration>,
    pub blk_io: u64,
    pub net_io: u64,
}

impl ContainerDetails {
    pub fn default() -> Result<Vec<Box<ContainerDetails>>, Error> {
        let docker = Docker::new();
        let mut container_datas = Vec::new();
        let containers = docker.containers().list(&Default::default())?;

        for c in containers {
            let name = match c.Names.get(0) {
                Some(x) => x,
                _ => return Err(format_err!("name not found for container")),
            };

            let mut pids = Vec::new();
            let top = docker.containers().get(name).top(None)?;
            for x in top.Processes {
                let pid = match x.get(1) {
                    Some(x) => x,
                    _ => return Err(format_err!("pid not found for container")),
                };
                pids.push(pid.to_string())
            }
            container_datas.push(Box::new(ContainerDetails {
                name: name.to_string(),
                id: c.Id,
                pids: pids,
                memory: HashMap::default(),
                usedcputime: HashMap::default(),
                blk_io: 0,
                net_io: 0,
            }));
        }
        Ok(container_datas)
    }
    pub fn get_mem(&self) -> Result<i32, Error> {
        let mut mem = 0;
        for index in 0..self.pids.len() {
            let pid = match self.pids.get(index) {
                Some(x) => x.to_string(),
                None => return Err(format_err!("pid not found")),
            };
            let status = procinfo::pid::status(pid.parse::<i32>()?)?;
            mem += status.vm_rss;
        }
        Ok(mem as i32)
    }

    pub fn get_vm_rss(&self) -> u64 {
        let mut total = 0 as u64;
        for (_pid, vm_rss) in &self.memory {
            total += vm_rss;
        }
        return total;
    }
    pub fn set_mem(&mut self, pid: String, mem: u64) {
        self.memory.insert(pid, mem);
    }

    pub fn get_cpu_runtime(&self, pid: &String) -> Result<f64, Error> {
        let mut total_runtime_in_nano = 0.0;
        let status = procinfo::pid::stat(pid.parse::<i32>()?)?;
        let utime = status.utime;
        let stime = status.stime;
        let cutime = status.cutime;
        let cstime = status.cstime;
        let total = utime + stime + cutime + cstime;
        total_runtime_in_nano += total as f64;
        total_runtime_in_nano = total_runtime_in_nano as f64 / tick_to_second() as f64;
        Ok(total_runtime_in_nano as f64)
    }

    pub fn set_cpu_runtime(&mut self, pid: String, time: time::Duration) {
        self.usedcputime.insert(pid, time);
    }

    pub fn add_cpu_runtime(&mut self, pid: String, nanosec: f64) {
        let time = match self.usedcputime.get(&pid) {
            Some(time) => time.as_nanos() + nanosec as u128,
            None => 0 as u128,
        };
        self.usedcputime
            .insert(pid, time::Duration::from_nanos(time as u64));
        // let nanos = self.usedcputime.as_nanos() + nanosec as u128;
        // self.usedcputime = time::Duration::from_nanos(nanos as u64);
    }
}

pub fn get_kmalloc_kfree_bpf(containers: &Vec<Box<ContainerDetails>>) -> Result<String, Error> {
    let mut pids = Vec::new();
    for container in containers {
        pids.extend(&container.pids);
    }
    let mut prog = String::new();
    let path = Path::new("/home/schoolboy/aarai/src/kmalloc_kfree.c");

    let mut f = File::open(&path)?;
    f.read_to_string(&mut prog);
    let mut reg = handlebars::Handlebars::new();
    return Ok(reg.render_template(&prog, &json!({ "pids": pids }))?);
}

pub fn tick_to_second() -> i64 {
    let seconds = unsafe { sysconf(_SC_CLK_TCK) };
    return seconds;
}

pub fn get_uptime() -> u64 {
    let mut f = File::open("/proc/uptime").expect("unable to open /proc/uptime");
    let mut content = String::new();
    f.read_to_string(&mut content)
        .expect("unable to read /proc/uptime");
    let uptime: Vec<&str> = content.split(" ").collect();
    let uptime = uptime[0];
    return String::from(uptime)
        .parse::<f64>()
        .expect("unable to parse") as u64 * 1000000000;
}

pub fn start_time_for_pid(pid: i32) -> u64 {
    let status = procinfo::pid::stat(pid).expect("unable to get status");
    return status.start_time;
}

pub fn get_vm_rss(pid: i32) -> Result<u64, Error> {
    let status = procinfo::pid::status(pid)?;
    return Ok(status.vm_rss as u64);
}

pub fn get_pid_runtime(pid: i32) -> Result<f64, Error> {
    let mut total_runtime: f64 = 0.0;
    let status = procinfo::pid::stat(pid)?;
    let utime = status.utime;
    let stime = status.stime;
    let cutime = status.cutime;
    let cstime = status.cstime;
    total_runtime = (utime + stime + cutime + cstime) as f64;
    total_runtime = (total_runtime / tick_to_second() as f64) * 1000000000.0;
    Ok(total_runtime)
}
