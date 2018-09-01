#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>
#include <linux/socket.h>
BPF_PERF_OUTPUT(blk_io_event);
BPF_PERF_OUTPUT(alloc_event);
BPF_PERF_OUTPUT(free_event);
BPF_PERF_OUTPUT(cpu_runtime_event);
BPF_PERF_OUTPUT(net_io_event);
BPF_PERF_OUTPUT(page_alloc_event);
BPF_PERF_OUTPUT(page_free_event);



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
// ends here
struct kmalloc_data
{
    u32 pid;
    u64 byte_alloc;
};

struct cpu_runtime
{
    u32 pid;
    u64 runtime;
    u64 vm_rss;
};

static __always_inline bool pid_exist(u32 val)
{
    u32 pids[] = {
        {{#each pids as | pid | ~}} {{pid}},
        {{ / each ~}}};

    int size = sizeof(pids) / sizeof(pids[0]);
    int i;
    for (i = 0; i < size; i++)
    {
        if (pids[i] == val)
            return true;
    }
    return false;
}
BPF_HASH(alloc_reference, u64, struct kmalloc_data);
int kmalloc_collector(struct tracepoint__kmem__kmalloc *args)
{
    int pids[] = {
        {{#each pids as | pid | ~}} {{pid}},
        {{ / each ~}}};

    int SIZE_OF_PIDS = sizeof(pids) / sizeof(pids[0]);
    u32 pid = bpf_get_current_pid_tgid();
    int size = SIZE_OF_PIDS;
    bool flag = false;
    u64 alloc = args->bytes_alloc;
    struct kmalloc_data data = {};
    data.pid = pid;
    data.byte_alloc = alloc;
    u64 converted_ptr = (size_t)args->ptr;
    for (int i = 0; i < size; i++)
    {
        if (pids[i] == pid)
        {
            flag = true;
        }
    }
    if (flag == false)
    {
        return 0;
    }
    else
    {
        alloc_event.perf_submit(args, &data, sizeof(data));
        alloc_reference.update(&converted_ptr, &data);
        return 0;
    }

    return 0;
}

int kfree_collector(struct tracepoint__kmem__kfree *args)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 converted_ptr = (size_t)args->ptr;
    struct kmalloc_data *data = alloc_reference.lookup(&converted_ptr);
    if (data != 0)
    {
        alloc_reference.delete(&converted_ptr);
        free_event.perf_submit(args, data, sizeof(*data));
        return 0;
    }
    return 0;
}

// rss value also will be calculated when context switches
int sched_stat_runtime_collector(struct tracepoint__sched__sched_stat_runtime *args)
{
    // my sync once implementation :P

    int pids[] = {
        {{#each pids as | pid | ~}} {{pid}},
        {{ / each ~}}};

    int SIZE_OF_PIDS = sizeof(pids) / sizeof(pids[0]);
    u32 pid = bpf_get_current_pid_tgid();
    int size = SIZE_OF_PIDS;
    struct task_struct *task;
    struct mm_struct *mm;
    task = (struct task_struct *)bpf_get_current_task();
    mm = NULL;
    bpf_probe_read(&mm, sizeof(mm), &task->mm);
    u64 total_rss = bpf_get_mm_rss(mm) << (PAGE_SHIFT - 10);
    bool flag = false;
    u64 runtime = args->runtime;
    struct cpu_runtime data = {};
    data.pid = pid;
    data.runtime = runtime;
    data.vm_rss = total_rss;
    for (int i = 0; i < size; i++)
    {
        if (pids[i] == pid)
        {
            flag = true;
        }
    }
    if (flag == false)
    {
        return 0;
    }
    else
    {
        cpu_runtime_event.perf_submit(args, &data, sizeof(data));
        return 0;
    }

    return 0;
}

struct blk_io_data
{
    u32 pid;
    u64 request_bytes;
};

int blk_io_collector(struct pt_regs *ctx, struct request *req)
{

    int pids[] = {
        {{#each pids as | pid | ~}} {{pid}},
        {{ / each ~}}};

    int SIZE_OF_PIDS = sizeof(pids) / sizeof(pids[0]);
    u32 pid = bpf_get_current_pid_tgid();
    int size = SIZE_OF_PIDS;
    bool flag = false;
    struct blk_io_data data = {};
    data.pid = pid;
    data.request_bytes = req->__data_len;
    for (int i = 0; i < size; i++)
    {
        if (pids[i] == pid)
        {
            flag = true;
        }
    }
    if (flag == false)
    {
        return 0;
    }
    else
    {
        blk_io_event.perf_submit(ctx, &data, sizeof(data));
        return 0;
    }
    return 0;
}

struct net_io_data
{
    u32 pid;
    u64 request_byte;
};

int send_to_tracepoint(struct tracepoint__syscalls__sys_enter_sendto *args)
{
    u32 pid = bpf_get_current_pid_tgid();

    if (pid_exist(pid))
    {
        struct net_io_data data = {};
        data.pid = pid;
        data.request_byte = args->len;
        net_io_event.perf_submit(args, &data, sizeof(data));
    }
    return 0;
}

int send_msg_tracepoint(struct tracepoint__syscalls__sys_enter_sendmsg *args)
{
    u32 pid = bpf_get_current_pid_tgid();

    if (pid_exist(pid))
    {
        struct msghdr *msg;
        msg = NULL;
        bpf_probe_read(&msg, sizeof(msg), &args->msg);
        struct net_io_data data = {};
        data.pid = pid;
        //data.request_byte = msg->msg_flags;
        net_io_event.perf_submit(args, &data, sizeof(data));
    }
    return 0;
}

int recv_from_tracepoint(struct tracepoint__syscalls__sys_enter_recvfrom *args)
{
    u32 pid = bpf_get_current_pid_tgid();

    if (pid_exist(pid))
    {
        struct net_io_data data = {};
        data.pid = pid;
        data.request_byte = args->size;
        net_io_event.perf_submit(args, &data, sizeof(data));
    }
    return 0;
}

int recv_msg_tracepoint(struct tracepoint__syscalls__sys_enter_recvmsg *args)
{
    u32 pid = bpf_get_current_pid_tgid();

    if (pid_exist(pid))
    {
        struct msghdr *msg;
        msg = NULL;
        bpf_probe_read(&msg, sizeof(msg), &args->msg);
        struct net_io_data data = {};
        data.pid = pid;
        //data.request_byte = msg->msg_flags;
        net_io_event.perf_submit(args, &data, sizeof(data));
    }
    return 0;
}