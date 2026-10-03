#include "TripWirePlatform.h"
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <wchar.h>
#include <stdlib.h>
#include <string.h>

// Local absolute paths only. Reject ADS, UNC/device paths and every existing
// reparse-point component. No permission repair, privilege changes or elevation.
static wchar_t *local_path(const char *path) {
    int count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, NULL, 0);
    if (count <= 0 || count > 32760) return NULL;
    wchar_t *p = calloc((size_t)count + 4, sizeof(wchar_t));
    if (!p || !MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, p, count)) { free(p); return NULL; }
    for (int i = 0; p[i]; i++) if (p[i] == L'/') p[i] = L'\\';
    // Foundation may expose the drive as /C:/path.
    if (p[0] == L'\\' && p[1] && p[2] == L':') memmove(p, p + 1, wcslen(p) * sizeof(wchar_t));
    if (!((p[0] >= L'A' && p[0] <= L'Z') || (p[0] >= L'a' && p[0] <= L'z')) || p[1] != L':' || p[2] != L'\\') { free(p); return NULL; }
    for (int i = 3; p[i]; i++) if (p[i] == L':' || p[i] == L'*' || p[i] == L'?') { free(p); return NULL; }
    wchar_t *full = calloc(32768, sizeof(wchar_t));
    DWORD n = full ? GetFullPathNameW(p, 32768, full, NULL) : 0; free(p);
    if (!n || n >= 32768) { free(full); return NULL; }
    for (DWORD i = 3; i <= n; i++) if (full[i] == L'\\' || full[i] == 0) {
        wchar_t saved = full[i]; full[i] = 0;
        DWORD attr = GetFileAttributesW(full);
        DWORD error = attr == INVALID_FILE_ATTRIBUTES ? GetLastError() : ERROR_SUCCESS;
        full[i] = saved;
        if ((attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_REPARSE_POINT)) ||
            (attr == INVALID_FILE_ATTRIBUTES && error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND)) { free(full); return NULL; }
    }
    return full;
}
static TOKEN_USER *current_user(void) {
    HANDLE token; DWORD size = 0;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return NULL;
    GetTokenInformation(token, TokenUser, NULL, 0, &size);
    TOKEN_USER *user = size && size < 65536 ? malloc(size) : NULL;
    if (user && !GetTokenInformation(token, TokenUser, user, size, &size)) { free(user); user = NULL; }
    CloseHandle(token); return user;
}
static PSECURITY_DESCRIPTOR private_descriptor(void) {
    TOKEN_USER *user = current_user(); LPWSTR sid = NULL;
    PSECURITY_DESCRIPTOR descriptor = NULL;
    if (user && ConvertSidToStringSidW(user->User.Sid, &sid)) {
        wchar_t text[512];
        int n = swprintf(text, 512, L"O:%lsD:P(A;OICI;FA;;;%ls)(A;OICI;FA;;;SY)", sid, sid);
        if (n > 0 && n < 512) ConvertStringSecurityDescriptorToSecurityDescriptorW(text, SDDL_REVISION_1, &descriptor, NULL);
    }
    if (sid) LocalFree(sid); free(user); return descriptor;
}
static int private_handle(HANDLE handle, int directory, uint64_t *size) {
    BY_HANDLE_FILE_INFORMATION info;
    if (GetFileType(handle) != FILE_TYPE_DISK || !GetFileInformationByHandle(handle, &info) ||
        (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) ||
        !!(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != !!directory || (!directory && info.nNumberOfLinks != 1)) return -1;
    PSID owner = NULL; PACL acl = NULL; PSECURITY_DESCRIPTOR sd = NULL;
    TOKEN_USER *user = current_user(); int valid = 0;
    if (user && GetSecurityInfo(handle, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &owner, NULL, &acl, NULL, &sd) == ERROR_SUCCESS &&
        owner && EqualSid(owner, user->User.Sid) && acl && acl->AceCount > 0) {
        BYTE system[SECURITY_MAX_SID_SIZE]; DWORD systemSize = sizeof(system);
        valid = CreateWellKnownSid(WinLocalSystemSid, NULL, system, &systemSize) != 0;
        for (DWORD i = 0; valid && i < acl->AceCount; i++) {
            ACE_HEADER *header = NULL;
            if (!GetAce(acl, i, (void **)&header)) { valid = 0; break; }
            if (header->AceType == ACCESS_ALLOWED_ACE_TYPE) {
                ACCESS_ALLOWED_ACE *ace = (ACCESS_ALLOWED_ACE *)header;
                PSID sid = &ace->SidStart;
                if (!IsValidSid(sid) || (!EqualSid(sid, user->User.Sid) && !EqualSid(sid, system))) valid = 0;
            } else if (header->AceType != ACCESS_DENIED_ACE_TYPE) valid = 0;
        }
    }
    if (sd) LocalFree(sd); free(user);
    if (valid && size) *size = ((uint64_t)info.nFileSizeHigh << 32) | info.nFileSizeLow;
    return valid ? 0 : -1;
}
int tw_private_info(const char *path, int directory, int missing_allowed, uint64_t *size) {
    wchar_t *p = local_path(path); if (!p) return -1;
    HANDLE h = CreateFileW(p, READ_CONTROL | FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, NULL);
    DWORD error = h == INVALID_HANDLE_VALUE ? GetLastError() : 0; free(p);
    if (h == INVALID_HANDLE_VALUE) return missing_allowed && (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) ? 1 : -1;
    int result = private_handle(h, directory, size); CloseHandle(h); return result;
}
int tw_private_directory(const char *path) {
    wchar_t *p = local_path(path); if (!p) return -1;
    PSECURITY_DESCRIPTOR sd = private_descriptor(); if (!sd) { free(p); return -1; }
    SECURITY_ATTRIBUTES attributes = {sizeof(attributes), sd, FALSE}; int ok = 1;
    size_t count = wcslen(p);
    for (size_t i = 3; ok && i <= count; i++) if (p[i] == L'\\' || p[i] == 0) {
        wchar_t saved = p[i]; p[i] = 0;
        if (!CreateDirectoryW(p, &attributes) && GetLastError() != ERROR_ALREADY_EXISTS) ok = 0;
        DWORD attr = GetFileAttributesW(p);
        if (attr == INVALID_FILE_ATTRIBUTES || !(attr & FILE_ATTRIBUTE_DIRECTORY) || (attr & FILE_ATTRIBUTE_REPARSE_POINT)) ok = 0;
        p[i] = saved;
    }
    free(p); LocalFree(sd); uint64_t ignored = 0;
    return ok ? tw_private_info(path, 1, 0, &ignored) : -1;
}
static HANDLE create_private(const char *path, DWORD disposition, DWORD sharing) {
    wchar_t *p = local_path(path); if (!p) return INVALID_HANDLE_VALUE;
    PSECURITY_DESCRIPTOR sd = private_descriptor(); if (!sd) { free(p); return INVALID_HANDLE_VALUE; }
    SECURITY_ATTRIBUTES attributes = {sizeof(attributes), sd, FALSE};
    HANDLE h = CreateFileW(p, GENERIC_READ | GENERIC_WRITE | READ_CONTROL, sharing, &attributes, disposition, FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    LocalFree(sd); free(p);
    if (h != INVALID_HANDLE_VALUE && private_handle(h, 0, NULL) != 0) { CloseHandle(h); h = INVALID_HANDLE_VALUE; }
    return h;
}
int tw_private_create(const char *path) {
    HANDLE h = create_private(path, CREATE_NEW, FILE_SHARE_READ | FILE_SHARE_WRITE);
    if (h == INVALID_HANDLE_VALUE) return -1; CloseHandle(h); return 0;
}
intptr_t tw_collector_lock(const char *path) { return (intptr_t)create_private(path, OPEN_ALWAYS, 0); }
void tw_collector_unlock(intptr_t handle) { CloseHandle((HANDLE)handle); }
#endif
