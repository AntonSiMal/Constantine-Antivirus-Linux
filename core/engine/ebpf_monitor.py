"""
Constantine Antivirus - eBPF Monitoring Engine (core/engine/ebpf_monitor.py)
"""
import os, logging, threading
from typing import Callable, Optional

logger = logging.getLogger("constantine.ebpf")

try:
    from bcc import BPF
    HAS_BCC = True
except ImportError:
    HAS_BCC = False

EBPF_PROBE_C = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define ARGSIZE 128

struct exec_event_t {
    u32 pid;
    u32 ppid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    char filename[256];
    char args[ARGSIZE];
};

struct ptrace_event_t {
    u32 pid;
    u32 target_pid;
    u32 request;
    char comm[TASK_COMM_LEN];
};

BPF_PERF_OUTPUT(exec_events);
BPF_PERF_OUTPUT(ptrace_events);

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct exec_event_t event = {};
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid();
    event.ppid = task->real_parent->tgid;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user_str(&event.filename, sizeof(event.filename), args->filename);
    const char __user *const __user *argp = args->argv;
    const char __user *first_arg;
    if (argp && bpf_probe_read_user(&first_arg, sizeof(first_arg), &argp[1]) == 0 && first_arg) {
        bpf_probe_read_user_str(&event.args, sizeof(event.args), first_arg);
    }
    exec_events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_ptrace) {
    struct ptrace_event_t event = {};
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.request = args->request;
    event.target_pid = args->pid;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    ptrace_events.perf_submit(args, &event, sizeof(event));
    return 0;
}
"""

class EBPFMonitor:
    def __init__(self, alert_callback: Optional[Callable] = None):
        self.alert_callback = alert_callback
        self.bpf = None
        self.running = False
        self.thread = None
        self.suspicious_binaries = {"nc", "ncat", "netcat", "socat", "xmrig"}
        self.suspicious_args = ["/dev/tcp/", "-e /bin/sh", "-e /bin/bash", "--exec", "pty.spawn", "base64 -d"]

    def start(self):
        if not HAS_BCC:
            return
        try:
            self.bpf = BPF(text=EBPF_PROBE_C)
            self.bpf["exec_events"].open_perf_buffer(self._on_exec)
            self.bpf["ptrace_events"].open_perf_buffer(self._on_ptrace)
            self.running = True
            self.thread = threading.Thread(target=self._poll, daemon=True)
            self.thread.start()
        except Exception:
            pass

    def _poll(self):
        while self.running:
            try:
                self.bpf.perf_buffer_poll(timeout=100)
            except Exception:
                break

    def _on_exec(self, cpu, data, size):
        event = self.bpf["exec_events"].event(data)
        comm = event.comm.decode("utf-8", "replace")
        filename = event.filename.decode("utf-8", "replace")
        args = event.args.decode("utf-8", "replace")
        base = os.path.basename(filename)
        if base in self.suspicious_binaries or any(p in args for p in self.suspicious_args) or filename.startswith(("/tmp/", "/dev/shm/")):
            if self.alert_callback:
                self.alert_callback(f"Behavior.SuspiciousExec.{base}", filename, event.pid, comm)

    def _on_ptrace(self, cpu, data, size):
        event = self.bpf["ptrace_events"].event(data)
        if event.request in (4, 5, 16) and self.alert_callback:
            comm = event.comm.decode("utf-8", "replace")
            self.alert_callback("Behavior.ProcessInjection.Ptrace", f"/proc/{event.target_pid}", event.pid, comm)

    def stop(self):
        self.running = False
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=1)
