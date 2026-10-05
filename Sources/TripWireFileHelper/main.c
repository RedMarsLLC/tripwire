// Session-only privileged launcher. No installation, arbitrary commands, paths,
// arguments, environment from the caller, or privileged filesystem writes.
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t interrupted = 0;
static void stop_signal(int signal_number) { (void)signal_number; interrupted = 1; }
static double uptime(void) {
    struct timespec value;
    clock_gettime(CLOCK_MONOTONIC, &value);
    return (double)value.tv_sec + (double)value.tv_nsec / 1000000000.0;
}
static int nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL);
    return flags < 0 ? -1 : fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}
static void status_line(const char *code) {
    char buffer[128];
    int length = snprintf(buffer, sizeof(buffer), "\nTRIPWIRE-HELPER/1 %s\n", code);
    // Best effort only: never block cleanup behind an absent/stalled reader.
    if (length > 0 && (size_t)length < sizeof(buffer)) (void)write(STDOUT_FILENO, buffer, (size_t)length);
}
int main(int argc, char **argv) {
    (void)argv;
    if (argc != 1 || geteuid() != 0 || isatty(STDIN_FILENO) || isatty(STDOUT_FILENO)) return 64;
    signal(SIGPIPE, SIG_IGN);
    signal(SIGTERM, stop_signal); signal(SIGINT, stop_signal); signal(SIGHUP, stop_signal);
    if (nonblocking(STDIN_FILENO) || nonblocking(STDOUT_FILENO)) return 74;
    // Require an initial application heartbeat before starting the event source.
    struct pollfd handshake = { STDIN_FILENO, POLLIN, 0 };
    unsigned char pulse;
    if (poll(&handshake, 1, 10000) <= 0 || read(STDIN_FILENO, &pulse, 1) != 1 || pulse != 'H') return 75;
    int output[2], errors[2];
    if (pipe(output) || pipe(errors)) return 71;
    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_addopen(&actions, STDIN_FILENO, "/dev/null", O_RDONLY, 0);
    posix_spawn_file_actions_adddup2(&actions, output[1], STDOUT_FILENO);
    posix_spawn_file_actions_adddup2(&actions, errors[1], STDERR_FILENO);
    posix_spawn_file_actions_addclose(&actions, output[0]);
    posix_spawn_file_actions_addclose(&actions, errors[0]);
    posix_spawn_file_actions_addclose(&actions, output[1]);
    posix_spawn_file_actions_addclose(&actions, errors[1]);
    posix_spawnattr_t attributes;
    posix_spawnattr_init(&attributes);
    // eslogger suppresses its process group; isolate it from the monitored app.
    posix_spawnattr_setflags(&attributes, POSIX_SPAWN_SETPGROUP | POSIX_SPAWN_CLOEXEC_DEFAULT);
    posix_spawnattr_setpgroup(&attributes, 0);
    char *const arguments[] = { "/usr/bin/eslogger", "open", "write", "close", "rename", "unlink", NULL };
    char *const environment[] = { "PATH=/usr/bin:/bin", "LANG=C", NULL };
    pid_t child;
    int result = posix_spawn(&child, "/usr/bin/eslogger", &actions, &attributes, arguments, environment);
    posix_spawn_file_actions_destroy(&actions); posix_spawnattr_destroy(&attributes);
    close(output[1]); close(errors[1]);
    if (result != 0) { close(output[0]); close(errors[0]); status_line("LAUNCH_FAILED"); return 71; }
    nonblocking(output[0]); nonblocking(errors[0]);
    // Bound memory. A full queue pauses child reads, applying pipe backpressure;
    // only a stalled reader causes shutdown, not an ordinary event burst.
    unsigned char pending[524288]; size_t used = 0, offset = 0;
    char error_text[8192]; size_t error_used = 0; error_text[0] = 0;
    double last_heartbeat = uptime();
    double last_output_progress = uptime();
    const char *finish = "STOPPED";
    int reaped = 0, child_status = 0;
    status_line("STARTED");
    while (!interrupted) {
        struct pollfd fds[] = {
            { STDIN_FILENO, POLLIN, 0 }, { output[0], used - offset < sizeof(pending) ? POLLIN : 0, 0 },
            { errors[0], POLLIN, 0 }, { STDOUT_FILENO, used > offset ? POLLOUT : 0, 0 }
        };
        int ready = poll(fds, 4, 250);
        if (ready < 0 && errno != EINTR) { finish = "PIPE_FAILED"; break; }
        if (fds[0].revents & (POLLIN | POLLHUP | POLLERR)) {
            unsigned char input[32]; ssize_t n = read(STDIN_FILENO, input, sizeof(input));
            if (n == 0) break;
            if (n < 0 && errno != EAGAIN && errno != EINTR) break;
            int quit = 0;
            for (ssize_t i = 0; i < n; ++i) {
                if (input[i] == 'H') last_heartbeat = uptime();
                else { quit = 1; break; } // S or any unsupported command stops.
            }
            if (quit) break;
        }
        if (uptime() - last_heartbeat > 10) { finish = "APP_UNRESPONSIVE"; break; }
        if (used > offset && uptime() - last_output_progress > 8) { finish = "BACKPRESSURE"; break; }
        if (fds[2].revents & (POLLIN | POLLHUP)) {
            char buffer[1024]; ssize_t n = read(errors[0], buffer, sizeof(buffer));
            if (n > 0 && error_used < sizeof(error_text) - 1) {
                size_t count = (size_t)n < sizeof(error_text) - 1 - error_used ? (size_t)n : sizeof(error_text) - 1 - error_used;
                memcpy(error_text + error_used, buffer, count); error_used += count; error_text[error_used] = 0;
            }
        }
        if (fds[3].revents & POLLOUT) {
            ssize_t n = write(STDOUT_FILENO, pending + offset, used - offset);
            if (n > 0) { offset += (size_t)n; last_output_progress = uptime(); }
            else if (n < 0 && errno != EAGAIN && errno != EINTR) { finish = "PIPE_FAILED"; break; }
            if (offset == used) offset = used = 0;
        }
        if (fds[1].revents & POLLIN) {
            if (offset) { memmove(pending, pending + offset, used - offset); used -= offset; offset = 0; }
            ssize_t n = used < sizeof(pending) ? read(output[0], pending + used, sizeof(pending) - used) : -1;
            if (n > 0) { if (used == 0) last_output_progress = uptime(); used += (size_t)n; }
            else if (n < 0 && errno != EAGAIN && errno != EINTR) { finish = "PIPE_FAILED"; break; }
        }
        pid_t ended = waitpid(child, &child_status, WNOHANG);
        if (ended == child) {
            reaped = 1;
            // Never send arbitrary tool error output, document names or raw logs.
            finish = strstr(error_text, "ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED") || strstr(error_text, "Full Disk Access") ? "FULL_DISK_ACCESS_REQUIRED" : "TOOL_EXITED";
            break;
        }
    }
    if (!reaped) {
        kill(child, SIGTERM);
        double deadline = uptime() + 1;
        while (uptime() < deadline) {
            if (waitpid(child, &child_status, WNOHANG) == child) { reaped = 1; break; }
            struct timespec pause = {0, 20000000}; nanosleep(&pause, NULL);
        }
        if (!reaped) { kill(child, SIGKILL); while (waitpid(child, &child_status, 0) < 0 && errno == EINTR) {} }
    }
    close(output[0]); close(errors[0]);
    status_line(finish);
    return strcmp(finish, "STOPPED") == 0 ? 0 : 1;
}
