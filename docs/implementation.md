# Supported Metrics
- CPU usage
- main memory usage (i.e RSS)
- disk io
- net io

(io will be differentiated by fd, if the fd is `accept`, `accept4` then it'll be net io)

## Initial seeding for the state machine

### BPF HASH - STATE_PPID

key - pid
value - container hash or container name (typically container hash)
ps: not able to store the char, so I'm storing vector index to identify the container.      

It's okay to use a workaround. If you have a better way to do, you're welcome to do

### BPF HASH - STATE_PID

key - pid
value - ppid
populate this on clone and fork which made by the pid belongs to the container

### BPF HASH - STATE_SCHED

check pid if it is available, update the RSS and runtime

key - pid
value - 
```
struct {
    u64 rss;
    unsigned long long runtime;
    unsigned long long start_time;
}
```

### BPF HASH - STATE_FD
This will be populated on fd which opens by accept or accept4

# PERF 

Two cases we use for, one is for signaling and other for passing the data

### signaling case
 
- sched (cpu cycle) to update the cpu and memory usage, use `state_sched_event`
### data passing

- read, write, send, send_to if it is in fd send it to `state_net_io` otherwise `state_disk_io`

## DRAWBACK

There may be some jitter on based on the time we start, have to figure out some smoothening mechanism

## Findings that need to be solved.
sched_data, the first value is missing during retrieval. have to check that

missing one task struct won't affect the overall metrics, 
metrics are used to get the precise thing, there is no point of building monitoring data, without precise data. But this not priority for POC. so I'm ignoring this for now.
#### building software is never been easy.

## Tracepoints

- `sys_exit_clone`: This tracepoint is called twice for every clone syscall, so map the current task pid with the `state_pid`, and initialize the sched_data for calculating RSS and runtime

if pid and tgid are in same in task struct use parent tgid, otherwise use current tgid. 

- `sys_enter_exit`: remove the pid from all the state hashmap

## This is the third iteration

When I'm doing the metrics calculation on aarai cpu cycle,  the data is removed by bpf program on its bpf cpu cycle. This lead to crashing and panicking 

### solution

send the data to userspace and do the calculations. simultaneously bpf program maintains it's own logic.

The perf output has to be sequential so that we can do the metrics calculation in the user space. 

still, there is a pitfall, What if the exit perf reaches before the runtime perf?

The solution would be delaying the exit perf polling.

I know this won't be an appropriate solution, but I don't want to re-architecture the system from the scratch.

### problem
perf sending a lot of data so it is really hard to do the calculation in userspace CPU cycles which we get. There should be some sampling mechanism to aggregate the metrics. Maybe I'm wrong or I'm not good enough to pull this off. 

