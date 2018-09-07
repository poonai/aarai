use failure::Error;
use shiplift::Docker;
extern crate procinfo;
use std::collections::HashMap;

extern crate handlebars;
extern crate libc;

#[repr(C)]
#[derive(Debug, Clone)]
pub struct sched_data {
    pub rss: u64,
    pub index: u32,
    pub pid: u32,
}

#[repr(C)]
pub struct exit_data {
    pub index: u32,
    pub pid: u32,
}

#[derive(Debug, Clone)]
pub struct ContainerDetails {
    pub name: String,
    pub id: String,
    pub pids: Vec<String>,
    pub memory: HashMap<String, u64>,
    pub sched_datas: HashMap<String, sched_data>,
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
                sched_datas: HashMap::default(),
            }));
        }
        Ok(container_datas)
    }
}

pub fn get_vm_rss(pid: i32) -> Result<u64, Error> {
    let status = procinfo::pid::status(pid)?;
    return Ok(status.vm_rss as u64);
}
