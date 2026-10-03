#include "TripWirePlatform.h"
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
// The Windows SDK gates IPv6 IP Helper table types on Winsock IPv6 declarations.
#include <ws2tcpip.h>
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <iphlpapi.h>
#include <sddl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static uint64_t ticks(FILETIME t) { return ((uint64_t)t.dwHighDateTime << 32) | t.dwLowDateTime; }
int tw_processes(TWProcess *rows, int capacity, int *limited) {
    *limited = 0; int count = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return -1;
    PROCESSENTRY32W entry; memset(&entry, 0, sizeof(entry)); entry.dwSize = sizeof(entry);
    if (!Process32FirstW(snapshot, &entry)) { CloseHandle(snapshot); return -1; }
    do {
        if (entry.th32ProcessID == 0) continue;
        if (count >= capacity) { *limited = 1; break; }
        TWProcess *row = &rows[count++]; memset(row, 0, sizeof(*row));
        row->pid = entry.th32ProcessID; row->parent_pid = entry.th32ParentProcessID;
        HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, entry.th32ProcessID);
        if (!process) { *limited = 1; continue; }
        FILETIME created, ended, kernel, user;
        if (GetProcessTimes(process, &created, &ended, &kernel, &user)) { row->started = ticks(created); row->cpu_ticks = ticks(kernel) + ticks(user); }
        else *limited = 1;
        wchar_t path[4096]; DWORD length = 4096;
        if (!QueryFullProcessImageNameW(process, 0, path, &length) || !WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, path, -1, row->path, sizeof(row->path), NULL, NULL)) { row->path[0] = 0; *limited = 1; }
        HANDLE token;
        if (OpenProcessToken(process, TOKEN_QUERY, &token)) {
            DWORD size = 0; GetTokenInformation(token, TokenUser, NULL, 0, &size);
            TOKEN_USER *info = size && size < 65536 ? malloc(size) : NULL; LPWSTR sid = NULL;
            if (info && GetTokenInformation(token, TokenUser, info, size, &size) && ConvertSidToStringSidW(info->User.Sid, &sid))
                WideCharToMultiByte(CP_UTF8, 0, sid, -1, row->account, sizeof(row->account), NULL, NULL);
            if (sid) LocalFree(sid); free(info); CloseHandle(token);
        }
        PROCESS_MEMORY_COUNTERS memory; memset(&memory, 0, sizeof(memory)); memory.cb = sizeof(memory);
        if (GetProcessMemoryInfo(process, &memory, sizeof(memory))) { row->memory_bytes = memory.WorkingSetSize; row->memory_valid = 1; }
        CloseHandle(process);
    } while (Process32NextW(snapshot, &entry));
    if (GetLastError() != ERROR_NO_MORE_FILES) *limited = 1;
    CloseHandle(snapshot); return count;
}
int tw_host(TWHost *host) {
    memset(host, 0, sizeof(*host)); FILETIME idle, kernel, user;
    if (GetActiveProcessorGroupCount() == 1 && GetSystemTimes(&idle, &kernel, &user) && ticks(kernel) >= ticks(idle)) {
        host->user = ticks(user); host->system = ticks(kernel) - ticks(idle); host->idle = ticks(idle); host->cpu_valid = 1;
    }
    MEMORYSTATUSEX memory; memset(&memory, 0, sizeof(memory)); memory.dwLength = sizeof(memory);
    if (GlobalMemoryStatusEx(&memory)) { host->total_memory = memory.ullTotalPhys; host->available_memory = memory.ullAvailPhys; host->memory_valid = 1; }
    return host->cpu_valid && host->memory_valid ? 0 : -1;
}
static void address4(char *out, DWORD value) {
    unsigned char *b = (unsigned char *)&value;
    snprintf(out, 64, "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
}
static void address6(char *out, const unsigned char *b, DWORD scope) {
    // IP Helper's TCP6/UDP6 scope DWORD is in network byte order, like its ports.
    const unsigned char *scope_bytes = (const unsigned char *)&scope;
    DWORD host_scope = ((DWORD)scope_bytes[0] << 24) | ((DWORD)scope_bytes[1] << 16) | ((DWORD)scope_bytes[2] << 8) | scope_bytes[3];
    int n = snprintf(out, 64, "%x:%x:%x:%x:%x:%x:%x:%x", (b[0]<<8)|b[1], (b[2]<<8)|b[3], (b[4]<<8)|b[5], (b[6]<<8)|b[7], (b[8]<<8)|b[9], (b[10]<<8)|b[11], (b[12]<<8)|b[13], (b[14]<<8)|b[15]);
    if (host_scope && n > 0 && n < 50) snprintf(out+n, (size_t)(64-n), "%%%lu", (unsigned long)host_scope);
}
static uint16_t port(DWORD value) { return (uint16_t)(((value & 255) << 8) | ((value >> 8) & 255)); }
int tw_sockets(TWSocket *rows, int capacity, int *limited) {
    *limited = 0; int count = 0;
    for (int kind = 0; kind < 4; kind++) {
        int tcp = kind < 2, ipv6 = kind % 2; ULONG family = ipv6 ? AF_INET6 : AF_INET; DWORD bytes = 0;
        DWORD status = tcp ? GetExtendedTcpTable(NULL, &bytes, FALSE, family, TCP_TABLE_OWNER_PID_ALL, 0) : GetExtendedUdpTable(NULL, &bytes, FALSE, family, UDP_TABLE_OWNER_PID, 0);
        if (status != ERROR_INSUFFICIENT_BUFFER || bytes < sizeof(DWORD) || bytes > 8388608) { *limited = 1; continue; }
        void *table = malloc(bytes); if (!table) { *limited = 1; continue; }
        status = tcp ? GetExtendedTcpTable(table, &bytes, FALSE, family, TCP_TABLE_OWNER_PID_ALL, 0) : GetExtendedUdpTable(table, &bytes, FALSE, family, UDP_TABLE_OWNER_PID, 0);
        if (status != NO_ERROR) { free(table); *limited = 1; continue; }
        DWORD length = *(DWORD *)table;
        for (DWORD i = 0; i < length; i++) {
            if (count >= capacity) { *limited = 1; break; }
            TWSocket *r = &rows[count++]; memset(r, 0, sizeof(*r)); r->tcp = tcp;
            if (tcp && !ipv6) { MIB_TCPROW_OWNER_PID *s = &((MIB_TCPTABLE_OWNER_PID *)table)->table[i]; r->pid=s->dwOwningPid; r->state=(int)s->dwState; r->local_port=port(s->dwLocalPort); r->remote_port=port(s->dwRemotePort); address4(r->local_address,s->dwLocalAddr); address4(r->remote_address,s->dwRemoteAddr); }
            if (tcp && ipv6) { MIB_TCP6ROW_OWNER_PID *s = &((MIB_TCP6TABLE_OWNER_PID *)table)->table[i]; r->pid=s->dwOwningPid; r->state=(int)s->dwState; r->local_port=port(s->dwLocalPort); r->remote_port=port(s->dwRemotePort); address6(r->local_address,s->ucLocalAddr,s->dwLocalScopeId); address6(r->remote_address,s->ucRemoteAddr,s->dwRemoteScopeId); }
            if (!tcp && !ipv6) { MIB_UDPROW_OWNER_PID *s = &((MIB_UDPTABLE_OWNER_PID *)table)->table[i]; r->pid=s->dwOwningPid; r->local_port=port(s->dwLocalPort); address4(r->local_address,s->dwLocalAddr); }
            if (!tcp && ipv6) { MIB_UDP6ROW_OWNER_PID *s = &((MIB_UDP6TABLE_OWNER_PID *)table)->table[i]; r->pid=s->dwOwningPid; r->local_port=port(s->dwLocalPort); address6(r->local_address,s->ucLocalAddr,s->dwLocalScopeId); }
        }
        free(table);
    }
    return count;
}
#endif
