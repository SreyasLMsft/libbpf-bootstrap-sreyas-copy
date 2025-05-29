import mmap
import os
import struct
import ctypes
import time
import platform
import re

SHM_NAME = "/bpf_shm"
TASK_COMM_LEN = 16

def get_define_value(header_path, macro):
    with open(header_path) as f:
        for line in f:
            m = re.match(rf'#define\s+{macro}\s+(\d+)', line)
            if m:
                return int(m.group(1))
    raise ValueError(f"{macro} not found in {header_path}")

def sizeof_size_t():
    return 8 if platform.architecture()[0] == '64bit' else 4

SMBDIAG_HEADER = os.path.join(os.path.dirname(__file__), "smbdiag.h")
MAX_ENTRIES = get_define_value(SMBDIAG_HEADER, "MAX_ENTRIES")
PAGE_SIZE = get_define_value(SMBDIAG_HEADER, "PAGE_SIZE")
SHM_SIZE = ((MAX_ENTRIES + 1) * PAGE_SIZE)
SHM_DATA_SIZE = (SHM_SIZE - 2 * sizeof_size_t()) // 10  # delete /10 later
class Metrics(ctypes.Union):
    _fields_ = [
        ("latency_ns", ctypes.c_ulonglong),
        ("retval", ctypes.c_int)
    ]

class Event(ctypes.Structure):
    _fields_ = [
        ("pid", ctypes.c_int),
        ("cmd_end_time_ns", ctypes.c_ulonglong),
        ("session_id", ctypes.c_ulonglong),
        ("mid", ctypes.c_ulonglong),
        ("smbcommand", ctypes.c_ushort),
        ("metric", Metrics),
        ("tool", ctypes.c_ubyte),
        ("is_compounded", ctypes.c_ubyte),
        ("task", ctypes.c_char * TASK_COMM_LEN)
    ]

def read_ringbuf():
    fd = os.open(f"/dev/shm{SHM_NAME}", os.O_RDWR)
    with mmap.mmap(fd, SHM_SIZE, flags= mmap.MAP_SHARED, prot=mmap.PROT_READ | mmap.PROT_WRITE) as m:
        while True:
            m.seek(0)
            head = struct.unpack_from("<Q", m, 0)[0]     # Read the head value
            tail = struct.unpack_from("<Q", m, 8)[0]     # Read the tail value
            print(f"[AOD] head={head}, tail={tail}")
            
            while tail != head:
            
                print(f"[AOD] Reading event at tail={tail} and head={head}")

                offset = tail % SHM_DATA_SIZE
                m.seek(16 + offset)  # Skip the head and tail fields
                raw = m.read(ctypes.sizeof(Event))
                if len(raw) < ctypes.sizeof(Event):
                    print("[AOD] Incomplete event data, skipping...")
                    break
                event = Event.from_buffer_copy(raw)
            
                print(f"[AOD] Event(pid={event.pid}, cmd_end_time_ns={event.cmd_end_time_ns}, "
                    f"session_id={event.session_id}, mid={event.mid}, smbcommand={event.smbcommand}, "
                    f"metric.latency_ns={event.metric.latency_ns}, tool={event.tool}, "
                    f"is_compounded={event.is_compounded}, task={event.task.decode(errors='ignore').strip()})")
               
                tail = (tail + ctypes.sizeof(Event))% SHM_DATA_SIZE  # Update tail position
            
            if tail != struct.unpack_from("<Q", m, 8)[0]:
                m.seek(8)
                m.write(struct.pack("<Q", tail))  # Update the tail
                m.flush()

            time.sleep(1)  # Sleep to avoid busy waiting

if __name__ == "__main__":
    read_ringbuf()
