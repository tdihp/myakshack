import bcc
from bcc import BPF
from bcc.containers import filter_by_containers
from bcc.utils import ArgString, printb
import bcc.utils as utils
from collections import defaultdict
from time import strftime
import ctypes as ct
import time
import datetime
import pprint


DEF_DEFAULTS = {
    "MAX_EVENT_SIZE":   4096,
    "MAX_EVENTS":       64,
    "LOOP_MAX":         32,     # max loop count
    "EXEC_STR_BITS":    7,      # 7 bits means highest value is 0b1111111
}

EVENT_TYPES = [
    None,
    "EVENT_EXEC",
    "EVENT_STDIN",
    "EVENT_STDOUT",
    "EVENT_EXIT",
    "EVENT_TRACE",
]

EVENT_NAMES = [
    '',
    'EXEC',
    'STDIN',
    'STDOUT',
    'EXIT',
    'TRACE',
]

DEF_BUILTINS = dict((k, i) for i, k in enumerate(EVENT_TYPES) if k)


bpf_text = r"""
/* we need to make sure buffer size larger than MAX_EVENT_SIZE
 * but also make sure value under 1 byte, and is a mask
 */
#define MAX_EXEC_STR_SIZE ((1<<(EXEC_STR_BITS)) - 1)
#define EXEC_STR_CLIP MAX_EXEC_STR_SIZE
#define CNISTR "CNI_COMMAND="
#define MAX_PAYLOAD_SIZE ((LOOP_MAX * 2 + 1) * EXEC_STR_CLIP)

#include <linux/sched.h>
#include <linux/fdtable.h>
#include <linux/fs.h>
#include <uapi/linux/magic.h>
#include <linux/uio.h>

struct msghdr_t {
    u64 timestamp_ns;
    u32 type;
    u32 pid;        /* pid of the current process */
    u32 cni_pid;   /* pid of the cni, for caller, tracked by inode */
    union {
        struct {
            u16 payload_size;
            u8 envs;
            u8 args;
        } ex;  /*extra detail*/
        int exit_code;
    };
    union {  /*comm gives sufficient space for additional info in write probe */
        char comm[TASK_COMM_LEN];
        const char __user *usrbuf;
    };
};

#define BUFFER_SIZE (MAX_EVENT_SIZE - sizeof(struct msghdr_t))

struct buffer_t {
    struct msghdr_t hdr;
    u8 payload[MAX_PAYLOAD_SIZE];
};

BPF_PERCPU_ARRAY (percpu_buffer, struct buffer_t, 1);

// allow at least 4 concurrent CNI to be captured at any time
BPF_RINGBUF_OUTPUT(buffer, MAX_EVENTS * MAX_EVENT_SIZE / 4096);

BPF_HASH(inode_map, unsigned int, u32); /* for stdin: pid, stdout: 0 */

struct pid_inode_t {
    unsigned int ino0;
    unsigned int ino1;
};
BPF_HASH(pid_inode_map, u32, struct pid_inode_t); /* for deallocating inode_map items */
BPF_HASH(pipe_write_map, u32, struct msghdr_t);  /* pid->hdr */

static inline int match_csistr(const char *s) {
    const char *c = CNISTR;
    int diff = 0;
    for (int i = 0; i < (sizeof(CNISTR)-1); i++) {
        diff = c[i] - s[i];
        if(diff) {
            return diff;
        }
    }
    return diff;
}

static inline struct file *compat_fget(struct files_struct *files, unsigned int fd)
{
    struct fdtable *fdt = files->fdt;
    if (fd >= fdt->max_fds) {
        return NULL;
    }
    /* I have no idea but this is the way to go, not fdt->fd[fd] */
    return *(fdt->fd + fd);
}

/*
static inline void dbg(u32 v1, u32 v2, u64 v3) {
    struct msghdr_t hdr = {};
    hdr.type = EVENT_TRACE;
    hdr.pid = v1;
    hdr.cni_pid = v2;
    hdr.timestamp_ns = v3;
    hdr.size = sizeof(hdr);
    bpf_get_current_comm(&hdr.comm, sizeof(hdr.comm));
    buffer.ringbuf_output(&hdr, sizeof(hdr), BPF_RB_FORCE_WAKEUP);
}
*/

static inline int on_execve(
    struct pt_regs *ctx,
    const char __user *filename,
	const char __user *const __user *__argv,
	const char __user *const __user *__envp) {
    /* 
     * Step 1: Make sure both stdin and stdout is pipe, get the inode for both.
     * Step 2: copy filename
     * Step 3: copy envs, make sure "CNI_COMMAND=" is among env
     * Step 4: copy args
     * Step 5: copy rest of the headers
     * Step 6: report
     * Step 7: save mappings
     */
    u64 now = bpf_ktime_get_ns();
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u64 pidtgid = bpf_get_current_pid_tgid();
    u32 u32zero = 0;
    bool positive = false;

    /* Step 1 */
    if (!task->files) {
        return 0;
    }
    struct file *file0 = compat_fget(task->files, 0);
    struct file *file1 = compat_fget(task->files, 1);
    if (file0 == NULL || file0->f_inode->i_sb->s_magic != PIPEFS_MAGIC ||
        file1 == NULL || file1->f_inode->i_sb->s_magic != PIPEFS_MAGIC)
    {
        return 0;
    }

    /* Step 2 */
    struct buffer_t* buf = percpu_buffer.lookup(&u32zero);
    if (buf == NULL) {
        return 0;
    }
    struct msghdr_t* hdr = &buf->hdr;
    u8 *payload_p = ((u8 *) buf->payload);
    int size = bpf_probe_read_user_str(payload_p, MAX_EXEC_STR_SIZE, filename);
    if (size < 0) {
        return 0;
    }
    size &= EXEC_STR_CLIP;
    payload_p += size;

    /* Step 3*/
    const char __user * strp;
    u32 i;
    for (i = 0; i < LOOP_MAX; i++) {
        strp = __envp[i];
        if (strp == NULL) {
            break;
        }
        size = bpf_probe_read_user_str(payload_p, MAX_EXEC_STR_SIZE, strp);
        if (size < 0) {
            return 0;
        }
        if (!positive) {
            positive = !match_csistr(payload_p);
        }
        size &= EXEC_STR_CLIP;
        payload_p += size;
    }
    hdr->ex.envs = i;
    if (!positive) {
        return 0;
    }

    /* step 4 */
    for (i = 0; i < LOOP_MAX; i++) {
        strp = __argv[i];
        if (strp == NULL) {
            break;
        }
        size = bpf_probe_read_user_str(payload_p, MAX_EXEC_STR_SIZE, strp);
        if (size < 0) {
            return 0;
        }
        size &= EXEC_STR_CLIP;
        payload_p += size;
    }
    hdr->ex.args = i;

    /* Step 5 */
    hdr->timestamp_ns = now;
    hdr->type = EVENT_EXEC;
    hdr->pid = task->parent->pid;  /*we use parent pid here*/
    hdr->cni_pid = pidtgid;
    bpf_get_current_comm(&hdr->comm, sizeof(hdr->comm));
    u32 msgsize = payload_p - ((u8 *) buf->payload);
    if (msgsize > BUFFER_SIZE) {
        msgsize = BUFFER_SIZE;
    }
    hdr->ex.payload_size = msgsize;
    msgsize += sizeof(*hdr);
    if (msgsize > MAX_EVENT_SIZE) {
        return 0;
    }
    buffer.ringbuf_output(buf, msgsize, 0);
    struct pid_inode_t inodes;
    inodes.ino0 = file0->f_inode->i_ino;
    inodes.ino1 = file1->f_inode->i_ino;
    pid_inode_map.insert(&hdr->cni_pid, &inodes);
    inode_map.insert(&inodes.ino0, &hdr->cni_pid);
    inode_map.insert(&inodes.ino1, &u32zero);
    // dbg(inodes.ino0, inodes.ino1, 0);
    return 0;
};


int syscall__execve(
    struct pt_regs *ctx,
    const char __user *filename,
    const char __user *const __user *__argv,
    const char __user *const __user *__envp)
{
    int result = on_execve(ctx, filename, __argv, __envp);
    return result;
}

int trace_pipe_write(
    struct pt_regs *ctx, struct kiocb *iocb, struct iov_iter *from)
{
    u64 now = bpf_ktime_get_ns();
    struct file *f = iocb->ki_filp;
    
    if (f == NULL || f->f_inode == NULL) {
        return 0;
    }
    unsigned int ino = f->f_inode->i_ino;
    if (ino == 0) {
        return 0;
    }

    u32 *cni_pid_p = inode_map.lookup(&ino);
    if (cni_pid_p == NULL) {
        return 0;
    }

    /* we do some simple iov verification to make sure it is our write call */
    if (from->nr_segs != 1 || from->iov_offset != 0 || from->iov == NULL) {
        return 0;
    }

    const char __user *usrbuf = from->iov->iov_base;
    if (usrbuf == NULL) {
        return 0;
    }

    u64 pidtgid = bpf_get_current_pid_tgid();
    struct msghdr_t hdr = {};
    hdr.timestamp_ns = now;
    hdr.type = EVENT_STDIN;
    hdr.pid = pidtgid;
    hdr.cni_pid = *cni_pid_p;
    hdr.ex.payload_size = from->count;  /* we are assuming count < 16bit*/
    hdr.usrbuf = usrbuf;
    if (hdr.cni_pid == 0) {
        hdr.cni_pid = pidtgid;
        hdr.type = EVENT_STDOUT;
    }
    pipe_write_map.insert(&hdr.pid, &hdr);
    return 0;
}

int trace_ret_pipe_write(struct pt_regs *ctx)
{
    u64 now = bpf_ktime_get_ns();
    u32 u32zero = 0;
    u64 pidtgid = bpf_get_current_pid_tgid();
    u32 pid = pidtgid;
    struct msghdr_t *hdrp = pipe_write_map.lookup(&pid);
    if (hdrp == NULL) {
        return 0;
    }
    const char __user *usrbuf = hdrp->usrbuf;
    struct buffer_t* buf = percpu_buffer.lookup(&u32zero);
    if (buf == NULL) {
        goto err;
    }
    struct msghdr_t *hdr = &buf->hdr;
    *hdr = *hdrp;

    int rtn = PT_REGS_RC(ctx);
    if (rtn <= 0) {
        goto err;
    }
    if (rtn > hdr->ex.payload_size) { /* how is this possible */
        goto err;
    }
    rtn &= 0xffff;  /* apparently, we clip to 16bits */
    u32 size = rtn>BUFFER_SIZE?BUFFER_SIZE:rtn;
    bpf_get_current_comm(&hdr->comm, sizeof(hdr->comm));
    u8 *payload = (u8 *)&buf->payload;
    int r = bpf_probe_read_user(payload, size, usrbuf);
    if (r != 0) {
        goto err;
    }
    hdr->ex.payload_size = size;
    buffer.ringbuf_output(buf, size + sizeof(*hdr), 0);
err:
    pipe_write_map.delete(&pid);
    return 0;
}

int on_sched_exit(struct tracepoint__sched__sched_process_exit *args) {
    u64 now = bpf_ktime_get_ns();
    u32 pid = args->pid;
    struct pid_inode_t *inodesp = pid_inode_map.lookup(&pid);
    if (inodesp == NULL) {
        return 0;
    }
    inode_map.delete(&inodesp->ino0);
    inode_map.delete(&inodesp->ino1);
    pid_inode_map.delete(&pid);
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct msghdr_t hdr = {};
    hdr.timestamp_ns = now;
    hdr.type = EVENT_EXIT;
    hdr.pid = pid;
    hdr.cni_pid = pid;
    hdr.exit_code = task->exit_code;
    __builtin_memcpy(&hdr.comm, &args->comm, sizeof(args->comm));
    buffer.ringbuf_output(&hdr, sizeof(hdr), 0);
    return 0;
}


"""

defs = DEF_BUILTINS.copy()
defs.update(DEF_DEFAULTS)
def_text = "\n".join("#define %s %s" % pair for pair in defs.items())
bpf_text = def_text + '\n' + bpf_text

b = BPF(text=bpf_text, debug=bcc.DEBUG_BTF|bcc.DEBUG_BPF|bcc.DEBUG_SOURCE)
first_ts = BPF.monotonic_time()
first_ts_real = time.time()
# b = BPF(text=bpf_text, debug=0xff)
execve_fnname = b.get_syscall_fnname("execve")
b.attach_kprobe(event=execve_fnname, fn_name="syscall__execve")
b.attach_kprobe(event='pipe_write', fn_name="trace_pipe_write")
b.attach_kretprobe(event='pipe_write', fn_name="trace_ret_pipe_write", maxactive=4096)
b.attach_tracepoint(tp='sched:sched_process_exit', fn_name='on_sched_exit')


def reltime(ts_ns):
    return 1e-9 * (ts_ns - first_ts)


def clocktime(ts_ns):
    return reltime(ts_ns) + first_ts_real


COMMON_LINE = '%(timestamp)s %(pid)7s %(cni_pid)7s %(comm)16s %(event_name)6s'
ENCODING = 'utf8'

def callback(ctx, data, size):
    print('=' * 80)
    event = b['buffer'].event(data)
    event_name = EVENT_NAMES[event.type]
    event_type = EVENT_TYPES[event.type]
    pid = event.pid
    cni_pid = event.cni_pid
    comm = event.comm.decode(ENCODING)
    timestamp = datetime.datetime.fromtimestamp(clocktime(event.timestamp_ns)).strftime('%H:%M:%S.%f')
    print(COMMON_LINE % locals())
    if event_type == 'EVENT_EXIT':
        exit_code = event.exit_code
        print("exit code: %d" % exit_code)
    else:
        payload_size = event.ex.payload_size
        offset = ct.sizeof(msghdr_t)
        payload = bytes(ct.cast(ct.byref(event, offset), ct.POINTER(ct.c_uint8 * payload_size)).contents)
        if event_type == 'EVENT_EXEC':
            nenvs = event.ex.envs
            nargs = event.ex.args
            strlist = payload.split(b'\0')
            fname = b'?'
            envs = [b'?%d=?' % i for i in range(nenvs)]
            args = [b'?%d' % i for i in range(nargs)]
            if strlist:
                fname = strlist.pop(0)
            if strlist:
                envs_found = strlist[:nenvs]
                envs[:len(envs_found)] = envs_found
                strlist[:nenvs] = []
            if strlist:
                args_found = strlist[:nargs]
                args[:len(args_found)] = args_found
                strlist[:nargs] = []
            args = [arg.decode(ENCODING) for arg in args]
            envs = dict(env.decode(ENCODING).split('=', 1) for env in envs)
            print('exe: %s %s' % (fname.decode(ENCODING), ' '.join(args)))
            print('envs:')
            pprint.pprint(envs)
        else:
            print('payload:')
            print(payload.decode(ENCODING))
            # if event.padding:
            #     d = ct.cast(ct.byref(event, ct.sizeof(msghdr_t)), ct.POINTER(ct.c_char * event.padding))
            


class ex_t(ct.Structure):
    _fields_ = [
        ('payload_size',    ct.c_uint16),
        ('envs',            ct.c_uint8),
        ('args',            ct.c_uint8),
    ]

class _U(ct.Union):
    _fields_ = [
        ('ex',              ex_t),
        ('exit_code',       ct.c_int32),
    ]

class msghdr_t(ct.Structure):
    _fields_ = [
        ('timestamp_ns',    ct.c_uint64),
        ('type',            ct.c_uint32),
        ('pid',             ct.c_uint32),
        ('cni_pid',         ct.c_uint32),
        ('u',               _U),
        ('comm',            ct.c_char * 16),
    ]
    _anonymous_ = ['u']

# loop with callback to print_event
b["buffer"].open_ring_buffer(callback)
b["buffer"]._event_class = msghdr_t
while 1:
    try:
        # print('fooooo')
        b.ring_buffer_poll()
    except KeyboardInterrupt:
        exit()
