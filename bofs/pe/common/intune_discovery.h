/*
 * Shared Intune host and device ID discovery.
 * Extracted from exchange.c and apps.c to eliminate duplication.
 */
#ifndef _INTUNE_DISCOVERY_H_
#define _INTUNE_DISCOVERY_H_

#include <windows.h>
#include <wincrypt.h>

/* Scan an IME log buffer for a *.manage.microsoft.com hostname.
 * If prefix is non-NULL, the hostname must start with that prefix.
 * Returns 1 and writes the hostname into out if found. */
int find_manage_host(const char *buf, DWORD len, const char *prefix,
                     char *out, int outsz);

/* Derive fef.<region>.manage.microsoft.com from any
 * <service>.<region>.manage.microsoft.com hostname. */
int derive_fef_host(const char *host, char *out, int outsz);

/* Scan all IME log files for a manage.microsoft.com hostname.
 * If prefix is non-NULL (e.g. "fef."), only return hosts starting
 * with that prefix. Returns 1 if found. */
int discover_host(char *out, int outsz, const char *prefix);

/* Discover the Intune device ID from the MDM enrollment certificate
 * in LocalMachine\My. Returns 1 if found. */
int discover_device_id(char *out, int outsz);

#endif /* _INTUNE_DISCOVERY_H_ */
