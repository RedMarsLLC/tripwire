#include "TripWirePlatform.h"
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
static DWORD input_mode, output_mode;
static int console_active;
static volatile LONG interrupted;
int tw_isatty(int output) { DWORD mode; return GetConsoleMode(GetStdHandle(output ? STD_OUTPUT_HANDLE : STD_INPUT_HANDLE), &mode) != 0; }
int tw_console_begin(void) {
    HANDLE input = GetStdHandle(STD_INPUT_HANDLE), output = GetStdHandle(STD_OUTPUT_HANDLE);
    if (!GetConsoleMode(input, &input_mode) || !GetConsoleMode(output, &output_mode)) return -1;
    if (!SetConsoleMode(output, output_mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING)) return -1;
    if (!SetConsoleMode(input, input_mode & ~(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_INPUT))) { SetConsoleMode(output, output_mode); return -1; }
    console_active = 1; return 0;
}
void tw_console_end(void) {
    if (!console_active) return;
    SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), input_mode);
    SetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), output_mode); console_active = 0;
}
int tw_console_key(int milliseconds) {
    HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
    DWORD wait = WaitForSingleObject(input, (DWORD)milliseconds);
    if (wait == WAIT_TIMEOUT) return -1;
    if (wait != WAIT_OBJECT_0) return -2;
    INPUT_RECORD event; DWORD count = 0;
    if (!ReadConsoleInputW(input, &event, 1, &count) || !count) return -2;
    if (event.EventType == KEY_EVENT && event.Event.KeyEvent.bKeyDown) {
        WCHAR value = event.Event.KeyEvent.uChar.UnicodeChar;
        if (value > 0 && value < 128) return (int)value;
    }
    return -1;
}
void tw_console_size(int *width, int *height) {
    CONSOLE_SCREEN_BUFFER_INFO info; *width = 80; *height = 24;
    if (GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &info)) {
        *width = info.srWindow.Right - info.srWindow.Left + 1; *height = info.srWindow.Bottom - info.srWindow.Top + 1;
    }
}
static BOOL WINAPI on_interrupt(DWORD type) {
    if (type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT || type == CTRL_CLOSE_EVENT || type == CTRL_SHUTDOWN_EVENT) { InterlockedExchange(&interrupted, 1); return TRUE; }
    return FALSE;
}
int tw_interrupt_begin(void) { InterlockedExchange(&interrupted, 0); return SetConsoleCtrlHandler(on_interrupt, TRUE) ? 0 : -1; }
int tw_interrupted(void) { return InterlockedCompareExchange(&interrupted, 0, 0) != 0; }
void tw_interrupt_end(void) { SetConsoleCtrlHandler(on_interrupt, FALSE); }
#endif
