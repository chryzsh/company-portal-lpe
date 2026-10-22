/*
 * Shared WinHTTP request helper for Intune API calls.
 * Merges exchange's http_get and apps' http_request into one function.
 */
#ifndef _INTUNE_HTTP_H_
#define _INTUNE_HTTP_H_

#include <windows.h>
#include <winhttp.h>
#include <wincrypt.h>

/*
 * Issue an HTTP request and return the heap-allocated response body
 * (caller frees with free()). Returns NULL on failure.
 *
 * method       - "GET" or "POST"
 * url          - full URL including query string
 * token        - Bearer token for the Authorization header
 * body         - request body for POST (NULL or "" for GET)
 * fullmetadata - if nonzero, sends Accept: application/json; odata=fullmetadata
 *                otherwise sends Content-Type: application/json
 * client_cert  - optional client certificate for mTLS (NULL to skip)
 * out_status   - receives the HTTP status code (may be NULL)
 */
char *http_request(const char *method, const char *url, const char *token,
                   const char *body, int fullmetadata,
                   PCCERT_CONTEXT client_cert, int *out_status);

#endif /* _INTUNE_HTTP_H_ */
