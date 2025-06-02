#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "shm_writer.h"
#include "smbdiag.h"

int main() {
    struct shm_ringbuf *shm_ptr;
    int shm_fd = init_shared_memory(SHM_NAME, SHM_SIZE, &shm_ptr);
    if (shm_fd < 0) {
        fprintf(stderr, "Failed to initialize shared memory\n");
        return 1;
    }

    struct event dummy = {
        .pid = 4242,
        .cmd_end_time_ns = 1234567890123456ULL,
        .session_id = 0xDEADBEEFDEADBEEFULL,
        .mid = 0xCAFEBABEULL,
        .smbcommand = 0x0001,
        .metric.retval = -10,
        .tool = 7,
        .is_compounded = 0,
        .task = "DUMMY"
    };

    // Write the dummy event to the ring buffer
    for(int i=0;i<30;i++){
    if (shm_ringbuf_write(shm_ptr, &dummy) < 0) {
        fprintf(stderr, "Failed to write dummy event to shared memory\n");
    } else {
        printf("Dummy event written to shared memory!\n");
    }
    }

    munmap(shm_ptr, SHM_SIZE);
    close(shm_fd);
    return 0;
}