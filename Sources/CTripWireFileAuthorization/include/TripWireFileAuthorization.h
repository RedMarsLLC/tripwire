#pragma once
#include <Security/Authorization.h>
#include <stdio.h>
// Local compatibility launcher, not a service installer. Authorization must
// already have been obtained interactively by the application.
OSStatus TripWireLaunchFileHelper(AuthorizationRef authorization, const char *helperPath, FILE **channel);
