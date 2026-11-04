"""
Constantine Antivirus - Fanotify Kernel Interceptor (core/engine/interceptor.py)
"""
import os, ctypes, select, logging
from core.engine.system_whitelist import SystemWhitelist

logger = logging.getLogger("constantine.interceptor")

FAN_CLASS_CONTENT = 0x00000004
FAN_CLOEXEC = 0x00000001
FAN_NONBLOCK = 0x00000002
FAN_MARK_ADD = 0x00000001
FAN_MARK_MOUNT = 0x00000010
FAN_OPEN_PERM = 0x00010000
FAN_EXEC_PERM = 0x00080000
FAN_ALLOW = 0x01
FAN_DENY = 0x02
FAN_EVENT_METADATA_LEN = 24

libc = ctypes.CDLL("libc.so.6", use_errno=True)

class FanotifyEventMetadata(ctypes.Structure):
    _fields_ = [
        ("event_len", ctypes.c_uint32),
        ("vers", ctypes.c_uint8),
        ("reserved", ctypes.c_uint8),
        ("metadata_len", ctypes.c_uint16),
        ("mask", ctypes.c_uint64),
        ("fd", ctypes.c_int32),
        ("pid", ctypes.c_int32),
    ]

class FanotifyResponse(ctypes.Structure):
    _fields_ = [
        ("fd", ctypes.c_int32),
        ("response", ctypes.c_uint32),
    ]

class FanotifyInterceptor:
    def __init__(self, scanner, vault=None, notifier=None, firewall=None):
        self.scanner = scanner
        self.vault = vault
        self.notifier = notifier
        self.firewall = firewall
        self.whitelist = SystemWhitelist()
        self.fan_fd = -1
        self.running = False

    def initialize(self) -> bool:
        if os.geteuid() != 0:
            return False
        flags = FAN_CLASS_CONTENT | FAN_NONBLOCK | FAN_CLOEXEC
        event_f_flags = os.O_RDONLY | os.O_CLOEXEC
        try:
            self.fan_fd = libc.fanotify_init(flags, event_f_flags)
            return self.fan_fd >= 0
        except Exception:
            return False

    def mark_directory(self, path: str, mark_mount: bool = False) -> bool:
        if self.fan_fd < 0:
            return False
        os.makedirs(path, exist_ok=True)
        flags = FAN_MARK_ADD | (FAN_MARK_MOUNT if mark_mount else 0)
        mask = FAN_OPEN_PERM | FAN_EXEC_PERM
        path_bytes = path.encode("utf-8")
        ret = libc.fanotify_mark(self.fan_fd, flags, ctypes.c_uint64(mask), -100, path_bytes)
        return ret >= 0

    def get_process_name(self, pid: int) -> str:
        try:
            with open(f"/proc/{pid}/comm", "r") as f:
                return f.read().strip()
        except Exception:
            return "desconocido"

    def respond(self, event_fd: int, decision: int):
        resp = FanotifyResponse(fd=event_fd, response=decision)
        try:
            os.write(self.fan_fd, bytes(resp))
        except Exception:
            pass

    def process_events(self):
        self.running = True
        poll = select.poll()
        poll.register(self.fan_fd, select.POLLIN)
        buffer_size = 4096

        while self.running:
            try:
                events = poll.poll(500)
                if not events:
                    continue
                raw_data = os.read(self.fan_fd, buffer_size)
                if not raw_data:
                    continue
                offset = 0
                while offset + FAN_EVENT_METADATA_LEN <= len(raw_data):
                    meta = FanotifyEventMetadata.from_buffer_copy(raw_data[offset:offset + FAN_EVENT_METADATA_LEN])
                    if meta.vers != 3:
                        break
                    event_fd = meta.fd
                    pid = meta.pid
                    if event_fd >= 0:
                        try:
                            target_path = os.readlink(f"/proc/self/fd/{event_fd}")
                        except Exception:
                            target_path = f"<fd:{event_fd}>"

                        # 1. Lista blanca de la distribución (Cero interrupción para binarios legítimos de APT)
                        if self.whitelist.is_trusted_system_binary(target_path):
                            self.respond(event_fd, FAN_ALLOW)
                        else:
                            # 2. Análisis estático / heurístico
                            proc_name = self.get_process_name(pid)
                            scan_res = self.scanner.scan_file(target_fd=event_fd, file_path=target_path)

                            if scan_res.is_malicious:
                                # Acción Autónoma Silenciosa: Bloquear y Aislar sin molestar al usuario con preguntas
                                self.respond(event_fd, FAN_DENY)
                                if self.vault and os.path.exists(target_path):
                                    self.vault.quarantine_file(target_path, scan_res.threat_name or "Malware")
                                if self.notifier:
                                    self.notifier.alert_threat_blocked(scan_res.threat_name or "Malware", target_path, pid, proc_name)
                                if self.firewall:
                                    self.firewall.isolate_pid(pid, terminate=False)
                            else:
                                self.respond(event_fd, FAN_ALLOW)

                        try:
                            os.close(event_fd)
                        except OSError:
                            pass
                    offset += meta.event_len
            except KeyboardInterrupt:
                break
            except Exception:
                pass
        self.stop()

    def stop(self):
        self.running = False
        if self.fan_fd >= 0:
            try:
                os.close(self.fan_fd)
            except OSError:
                pass
            self.fan_fd = -1
