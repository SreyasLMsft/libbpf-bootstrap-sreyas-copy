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

HEAD_TAIL_BYTES = 8 if platform.architecture()[0] == '64bit' else 4

SMBDIAG_HEADER = os.path.join(os.path.dirname(__file__), "smbdiag.h")
MAX_ENTRIES = get_define_value(SMBDIAG_HEADER, "MAX_ENTRIES")
PAGE_SIZE = get_define_value(SMBDIAG_HEADER, "PAGE_SIZE")
SHM_SIZE = ((MAX_ENTRIES + 1) * PAGE_SIZE)
SHM_DATA_SIZE = (SHM_SIZE - 2 * HEAD_TAIL_BYTES) // 10  # delete /10 later
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
    cnt=0;
    fd = os.open(f"/dev/shm{SHM_NAME}", os.O_RDWR)
    with mmap.mmap(fd, SHM_SIZE, flags=mmap.MAP_SHARED, prot=mmap.PROT_READ | mmap.PROT_WRITE) as m:
        while True:
            m.seek(0)
            head = struct.unpack_from("<Q", m, 0)[0]
            tail = struct.unpack_from("<Q", m, 8)[0]
            print(f"[AOD] head={head}, tail={tail}")

            event_size = ctypes.sizeof(Event)
            events = []

            if tail == head:
                time.sleep(1)
                continue

            if tail < head:
                available = head - tail
                count = available // event_size
                offset = tail % SHM_DATA_SIZE
                m.seek(2 * HEAD_TAIL_BYTES + offset)
                raw = m.read(count * event_size)
                for i in range(count):
                    event_raw = raw[i*event_size:(i+1)*event_size]
                    event = Event.from_buffer_copy(event_raw)
                    events.append(event)
                tail = (tail + count * event_size) % SHM_DATA_SIZE
            else:
                # First chunk: from tail to end of buffer
                offset = tail % SHM_DATA_SIZE
                first_chunk_size = SHM_DATA_SIZE - offset
                count1 = first_chunk_size // event_size
                m.seek(2 * HEAD_TAIL_BYTES + offset)
                raw1 = m.read(count1 * event_size)
                # Second chunk: from start of buffer to head
                count2 = (head % SHM_DATA_SIZE) // event_size
                m.seek(2 * HEAD_TAIL_BYTES)
                raw2 = m.read(count2 * event_size)

                for i in range(count1):
                    event_raw = raw1[i*event_size:(i+1)*event_size]
                    event = Event.from_buffer_copy(event_raw)
                    events.append(event)
                for i in range(count2):
                    event_raw = raw2[i*event_size:(i+1)*event_size]
                    event = Event.from_buffer_copy(event_raw)
                    events.append(event)
                tail = (tail + (count1 + count2) * event_size) % SHM_DATA_SIZE

            # Process all events
            for event in events:
                cnt+=1
                print(f"[AOD] Count {cnt}")
                print(f"[AOD] Event(pid={event.pid}, cmd_end_time_ns={event.cmd_end_time_ns}, "
                      f"session_id={event.session_id}, mid={event.mid}, smbcommand={event.smbcommand}, "
                      f"metric.latency_ns={event.metric.latency_ns}, tool={event.tool}, "
                      f"is_compounded={event.is_compounded}, task={event.task.decode(errors='ignore').strip()})")

            # Update tail in shared memory
            m.seek(8)
            m.write(struct.pack("<Q", tail))
            m.flush()

            time.sleep(1)

if __name__ == "__main__":
    read_ringbuf()
