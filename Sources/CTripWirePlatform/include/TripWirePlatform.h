#ifndef TRIPWIRE_PLATFORM_H
#define TRIPWIRE_PLATFORM_H
#include <stdint.h>
#include <stddef.h>
int tw_sha256(const uint8_t *bytes, size_t count, uint8_t digest[32]);
// Windows private-store operations. Return -1 on any unverifiable condition.
int tw_private_info(const char *path, int directory, int missing_allowed, uint64_t *size);
int tw_private_directory(const char *path);
int tw_private_create(const char *path);
intptr_t tw_collector_lock(const char *path);
void tw_collector_unlock(intptr_t handle);
int tw_isatty(int output);
int tw_console_begin(void);
void tw_console_end(void);
int tw_console_key(int milliseconds);
void tw_console_size(int *width, int *height);
int tw_interrupt_begin(void);
int tw_interrupted(void);
void tw_interrupt_end(void);
typedef struct {
    uint32_t pid, parent_pid;
    uint64_t started, cpu_ticks, memory_bytes;
    int memory_valid;
    char path[4096], account[192];
} TWProcess;
int tw_processes(TWProcess *rows, int capacity, int *limited);
typedef struct {
    uint64_t user, system, idle, total_memory, available_memory;
    int cpu_valid, memory_valid;
} TWHost;
int tw_host(TWHost *host);
typedef struct {
    uint32_t pid;
    uint16_t local_port, remote_port;
    int tcp, state;
    char local_address[64], remote_address[64];
} TWSocket;
int tw_sockets(TWSocket *rows, int capacity, int *limited);
#endif
