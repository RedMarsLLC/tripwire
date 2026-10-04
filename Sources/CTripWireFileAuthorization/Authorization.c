#include "TripWireFileAuthorization.h"
OSStatus TripWireLaunchFileHelper(AuthorizationRef authorization, const char *helperPath, FILE **channel) {
    char *arguments[] = { NULL };
    // Deliberate, isolated local-build compatibility path. The app reports API
    // failures as unavailable; no sudo, shell, service install or silent grant.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    return AuthorizationExecuteWithPrivileges(authorization, helperPath, kAuthorizationFlagDefaults, arguments, channel);
#pragma clang diagnostic pop
}
