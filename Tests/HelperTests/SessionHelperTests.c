// Standalone test target. Exercise the real transport loop without root, TCC,
// or eslogger. Only this test replaces authorization and the spawned producer.
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static const char *fixture_executable;
static uid_t fixture_root(void) { return 0; }
static int fixture_spawn(pid_t *pid, const char *path, const posix_spawn_file_actions_t *actions,
                         const posix_spawnattr_t *attributes, char *const arguments[], char *const environment[]) {
    assert(strcmp(path, "/usr/bin/eslogger") == 0);
    assert(strcmp(arguments[1], "open") == 0 && strcmp(arguments[5], "unlink") == 0 && arguments[6] == NULL);
    char *const fixture_args[] = { (char *)fixture_executable, "--fixture", NULL };
    return posix_spawn(pid, fixture_executable, actions, attributes, fixture_args, environment);
}
#define main helper_entry
#define geteuid fixture_root
#define posix_spawn fixture_spawn
#include "../../Sources/TripWireFileHelper/main.c"
#undef main
#undef geteuid
#undef posix_spawn

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--fixture") == 0) {
        char bytes[8192]; memset(bytes, 'F', sizeof(bytes));
        for (int i = 0; i < 256; ++i) {
            size_t sent = 0;
            while (sent < sizeof(bytes)) {
                ssize_t count = write(STDOUT_FILENO, bytes + sent, sizeof(bytes) - sent);
                if (count < 0) return 1;
                sent += (size_t)count;
            }
        }
        // Stay alive until the real helper terminates this owned producer.
        for (;;) pause();
    }
    fixture_executable = argv[0];
    for (int close_pipe = 0; close_pipe < 2; ++close_pipe) {
        int channel[2]; assert(socketpair(AF_UNIX, SOCK_STREAM, 0, channel) == 0);
        pid_t helper = fork(); assert(helper >= 0);
        if (helper == 0) {
            close(channel[0]); dup2(channel[1], STDIN_FILENO); dup2(channel[1], STDOUT_FILENO); close(channel[1]);
            char *args[] = { "TEST-ONLY", NULL }; _exit(helper_entry(1, args));
        }
        close(channel[1]); assert(write(channel[0], "H", 1) == 1);
        struct timespec delay = {1, 0}; nanosleep(&delay, NULL); // Saturate the 512 KiB queue.
        double deadline = uptime() + 5, pulse_at = uptime();
        size_t fixture_bytes = 0;
        char status[1024] = {0}; size_t status_count = 0;
        while (fixture_bytes < 2097152 && uptime() < deadline) {
            struct pollfd descriptor = { channel[0], POLLIN, 0 };
            if (poll(&descriptor, 1, 100) > 0) {
                char buffer[32768]; ssize_t count = read(channel[0], buffer, sizeof(buffer));
                assert(count > 0);
                for (ssize_t i = 0; i < count; ++i) {
                    if (buffer[i] == 'F') fixture_bytes++;
                    else if (status_count < sizeof(status) - 1) status[status_count++] = buffer[i];
                }
                assert(strstr(status, "BACKPRESSURE") == NULL);
            }
            if (uptime() - pulse_at > 1) { assert(write(channel[0], "H", 1) == 1); pulse_at = uptime(); }
        }
        assert(fixture_bytes == 2097152);
        if (close_pipe) close(channel[0]); else assert(write(channel[0], "S", 1) == 1);
        int status_code = 0, ended = 0; deadline = uptime() + 3;
        while (uptime() < deadline) {
            if (waitpid(helper, &status_code, WNOHANG) == helper) { ended = 1; break; }
            struct timespec tick = {0, 20000000}; nanosleep(&tick, NULL);
        }
        assert(ended && WIFEXITED(status_code) && WEXITSTATUS(status_code) == 0);
        if (!close_pipe) close(channel[0]);
    }
    puts("PASS: saturated buffer drains losslessly; explicit stop and app disconnect terminate the helper");
    return 0;
}
