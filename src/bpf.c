#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>
#include <linux/socket.h>

// vakiyam struct it'll be very useful for parsing string
struct vakiyam
{
    char data[100];
};

struct sched_data
{
    u64 rss;
    unsigned long long runtime;
    unsigned long long start_time;
};

//new definitions
BPF_HASH(state_ppid, u32, u32);
BPF_HASH(state_pid, u32, u32);
BPF_HASH(state_sched, u32, struct sched_data);
BPF_HASH(state_fd);
BPF_PERF_OUTPUT(state_sched_event);
BPF_PERF_OUTPUT(state_net_io);
BPF_PERF_OUTPUT(state_disk_io);

// helpers man
static __always_inline unsigned long bpf_get_mm_counter(struct mm_struct *mm,
                                                        int member)
{
    long val;

    bpf_probe_read(&val, sizeof(val), &mm->rss_stat.count[member]);
    if (val < 0)
        val = 0;

    return (unsigned long)val;
}

static __always_inline unsigned long bpf_get_mm_rss(struct mm_struct *mm)
{
    return bpf_get_mm_counter(mm, MM_FILEPAGES) +
           bpf_get_mm_counter(mm, MM_ANONPAGES) +
           bpf_get_mm_counter(mm, MM_SHMEMPAGES);
}

int sched_tracepoint(struct tracepoint__sched__sched_stat_runtime *args)
{
    u32 pid = bpf_get_current_pid_tgid();
    u32 *pid_exist = state_pid.lookup(&pid);
    if (pid_exist == 0)
    {
        //state_sched_event.perf_submit(args, &pid, sizeof(pid));
        return 0;
    }
    struct sched_data *data = state_sched.lookup(&pid);
    if (data == 0)
    {
        return 0;
    }

    struct task_struct *task;
    struct mm_struct *mm;
    task = (struct task_struct *)bpf_get_current_task();
    mm = NULL;
    bpf_probe_read(&mm, sizeof(mm), &task->mm);
    u64 total_rss = bpf_get_mm_rss(mm) << (PAGE_SHIFT - 10);
    struct sched_data temp = {};
    temp.rss = total_rss;
    temp.runtime = args->runtime + data->runtime;
    temp.start_time = data->start_time;
    state_sched.update(&pid, &temp);
    state_sched_event.perf_submit(args, &pid, sizeof(pid));
    return 0;
}