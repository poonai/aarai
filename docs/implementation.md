# Supported Metrics
- cpu usage
- main memory usage (i.e rss)
- disk io
- net io

(io will be diffrentiated by fd, if the fd is accept, accept4 then it'll be net io)

## Initial seeding for state machine

### BPF HASH - STATE_PPID

key - pid
value - container hash or container name (typically container hash)
ps: not able to store the char, I don't know, so I'm storing vector index for identifyiing that pid is belong that particular container. 
|It's okay to keep use workaround. If you have better way to do, you're welcome to do|

### BPF HASH - STATE_PID

key - pid
value - ppid

populated on initial seeding as well when new clone or fork made by the pid belongs to the container

### BPF HASH - STATE_SCHED

check pid if it is available, update the rss and runtime

key - pid
value - 
```
struct {
    u64 rss;
    unsigned long long runtime;
    unsigned long long start_time;
}
```
populated intial with intial pids

### BPF HASH - STATE_FD
This will be populated on fd which opens by accept or accept4

# PERF 

Two case we use for, one is signaling and passing the data

### signaling case
 
- sched (cpu cycle) to updated cpu and memory usage, use `state_sched_event`
### data passing

- read, write, send, send_to if it is in fd send it to `state_net_io` otherwise `state_disk_io`

## DRAWBACK

There may be some jiiter on based on the time we start, have to figureout some smoothening mechanism

## SIMPLICITY

for time being make use of  `bpf_get_current_comm()` for comparison 

## Findings that need to be solved.
sched_data, first value is missing on retrival. have to check that

missing one task struct overall metrics, 
metrics is used to get precise thing, there is no point of building monitoring data, without precise data. But this not priority for POC. so I'm ignoring this for now.
#### building software is never been easy.

## Tracepoints

- `sys_exit_clone`: This tracepoint is called twice for every clone syscall, so map the current task pid with the `state_pid`, and initialze the sched_data for calcuating rss and runtime
