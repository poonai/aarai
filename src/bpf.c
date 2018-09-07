#include <linux/blkdev.h>

struct sched_data
{
    u64 rss;
    u32 index;
    u32 pid;
};

struct exit_data
{
    u32 pid;
    u32 index;
};

//new definitions
BPF_HASH(state_ppid, u32, u32);
BPF_HASH(state_pid, u32, u32);
BPF_HASH(state_sched, u32, struct sched_data);
BPF_PERF_OUTPUT(state_sched_event);
BPF_PERF_OUTPUT(exit_event);

// helpers man

static __always_inline unsigned long bpf_get_mm_counter(struct mm_struct *mm, int member)
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
    u32 *index = state_ppid.lookup(&pid);
    if (index == 0)
    {
        return 0;
    }
    struct sched_data temp = {};
    temp.pid = pid;
    temp.index = *index;
    temp.rss = total_rss;
    state_sched.update(&pid, &temp);
    state_sched_event.perf_submit(args, &temp, sizeof(temp));
    return 0;
}

int clone_tracepoint(struct tracepoint__syscalls__sys_exit_clone *args)
{
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    u32 tgid = task->tgid;
    u32 pid = bpf_get_current_pid_tgid();
    if (tgid == pid)
    {
        tgid = task->parent->tgid;
    }
    u32 *data = state_pid.lookup(&tgid);
    if (data == 0)
    {
        return 0;
    }
    u32 data_clone = *data;
    u32 *index = state_ppid.lookup(&data_clone);
    if (index == 0)
    {
        return 0;
    }

    state_pid.lookup_or_init(&pid, &tgid);
    struct sched_data temp = {};
    temp.index = *index;
    temp.pid = pid;
    temp.rss = 0;
    u32 index_clone = *index;
    state_ppid.lookup_or_init(&pid, &index_clone);
    state_sched.lookup_or_init(&pid, &temp);
    state_sched_event.perf_submit(args, &temp, sizeof(temp));
    return 0;
}

// don't do anything, revist here after the mem calculation are done properly
int exit_tracepoint(struct tracepoint__syscalls__sys_enter_exit *args)
{

    u32 pid = bpf_get_current_pid_tgid();
    u32 *data = state_pid.lookup(&pid);
    if (data == 0)
    {
        return 0;
    }
    u32 *index = state_ppid.lookup(&pid);
    if (index == 0)
    {
        return 0;
    }

    struct exit_data event = {};
    u32 temp_index = *index;
    event.index = temp_index;
    event.pid = pid;
    exit_event.perf_submit(args, &event, sizeof(event));
    state_pid.delete(&pid);
    state_ppid.delete(&pid);
    state_sched.delete(&pid);
    return 0;
}
int exit_group_tracepoint(struct tracepoint__syscalls__sys_enter_exit_group *args)
{
    u32 pid = bpf_get_current_pid_tgid();
    u32 *data = state_pid.lookup(&pid);
    if (data != 0)
    {
        return 0;
    }
    u32 *index = state_ppid.lookup(&pid);
    if (index == 0)
    {
        return 0;
    }
    state_pid.delete(&pid);
    state_ppid.delete(&pid);
    state_sched.delete(&pid);
    struct exit_data event = {};
    event.index = *index;
    event.pid = pid;
    exit_event.perf_submit(args, &event, sizeof(event));
    return 0;
}
