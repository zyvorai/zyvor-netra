// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "../netra_l7.h"

static struct netra_l7_work wk;

// work copies len payload bytes into the parser work area the way the
// datapath does: at most NETRA_L7_BUF_LEN of them.
static struct netra_l7_work *work(const void *p, size_t len)
{
    memset(&wk, 0, sizeof(wk));
    if (len > NETRA_L7_BUF_LEN) len = NETRA_L7_BUF_LEN;
    memcpy(wk.buf, p, len);
    wk.n = (int)len;
    return &wk;
}

// ---- DNS qname -------------------------------------------------------

static void dns_qname_multi_label(void)
{
    // 12-byte DNS header (ignored) + "www.example.com" as length-prefixed labels.
    unsigned char p[12 + 1 + 3 + 1 + 7 + 1 + 3 + 1] = {0};
    unsigned char *q = p + 12;
    *q++ = 3; memcpy(q, "www", 3); q += 3;
    *q++ = 7; memcpy(q, "example", 7); q += 7;
    *q++ = 3; memcpy(q, "com", 3); q += 3;
    *q++ = 0;
    char out[96] = {0};
    int n = netra_l7_dns_qname(work(p, sizeof(p)), out);
    assert(n == 15);
    assert(strcmp(out, "www.example.com") == 0);
}

static void dns_qname_uppercase_is_lowercased(void)
{
    unsigned char p[12 + 1 + 3 + 1] = {0};
    unsigned char *q = p + 12;
    *q++ = 3; memcpy(q, "FOO", 3); q += 3;
    *q++ = 0;
    char out[96] = {0};
    int n = netra_l7_dns_qname(work(p, sizeof(p)), out);
    assert(n == 3);
    assert(strcmp(out, "foo") == 0);
}

static void dns_qname_truncated_mid_label(void)
{
    // Header + a label claiming length 5 but only one name byte follows
    // before data_end. The parser is a byte-at-a-time bounds-checked
    // decode, so it should safely return the partial name it managed to
    // read rather than reading past data_end or returning garbage.
    unsigned char p[14] = {0};
    p[12] = 5;
    p[13] = 'h';
    char out[96] = {0};
    int n = netra_l7_dns_qname(work(p, sizeof(p)), out);
    assert(n == 1);
    assert(strcmp(out, "h") == 0);
}

static void dns_qname_compression_pointer_is_rejected(void)
{
    // A length byte with the top two bits set is a DNS compression
    // pointer, which this parser deliberately does not support.
    unsigned char p[14] = {0};
    p[12] = 0xC0;
    p[13] = 0x0C;
    char out[96] = {0};
    int n = netra_l7_dns_qname(work(p, sizeof(p)), out);
    assert(n == 0);
}

static void dns_qname_empty_buffer(void)
{
    unsigned char p[8] = {0}; // shorter than the 12-byte header
    char out[96] = {0};
    assert(netra_l7_dns_qname(work(p, sizeof(p)), out) == 0);
}

// ---- TLS ClientHello SNI ----------------------------------------------

// writeSNI writes a minimal server_name extension (RFC 6066 shape) at
// offset `at` in buffer p: ext_type=0x0000, ext_len, list_len,
// name_type=0x00, name_len, name bytes.
static void write_sni(unsigned char *p, int at, const char *name)
{
    int name_len = (int)strlen(name);
    p[at + 0] = 0x00; p[at + 1] = 0x00; // extension_type = server_name
    p[at + 2] = 0x00; p[at + 3] = (unsigned char)(2 + 1 + 2 + name_len); // ext_len
    p[at + 4] = 0x00; p[at + 5] = (unsigned char)(1 + 2 + name_len);     // list_len
    p[at + 6] = 0x00;                                                    // name_type = host_name
    p[at + 7] = 0x00; p[at + 8] = (unsigned char)name_len;                // name_len
    memcpy(p + at + 9, name, (size_t)name_len);
}

static void write_client_hello_header(unsigned char *p)
{
    p[0] = 0x16; // handshake record
    p[5] = 0x01; // ClientHello
}

static void tls_sni_found(void)
{
    unsigned char p[160] = {0};
    write_client_hello_header(p);
    write_sni(p, 43, "example.com");
    char out[96] = {0};
    int n = netra_l7_tls_sni(work(p, sizeof(p)), out);
    assert(n == 11);
    assert(strcmp(out, "example.com") == 0);
}

static void tls_sni_uppercase_is_lowercased(void)
{
    unsigned char p[160] = {0};
    write_client_hello_header(p);
    write_sni(p, 43, "Example.COM");
    char out[96] = {0};
    int n = netra_l7_tls_sni(work(p, sizeof(p)), out);
    assert(n == 11);
    assert(strcmp(out, "example.com") == 0);
}

static void tls_sni_no_extension_present(void)
{
    // Valid ClientHello header, no server_name extension anywhere: every
    // byte after the header is zero, which makes name_len decode to 0
    // at every scan offset, so the parser must never match.
    unsigned char p[160] = {0};
    write_client_hello_header(p);
    char out[96] = {0};
    assert(netra_l7_tls_sni(work(p, sizeof(p)), out) == 0);
}

static void tls_sni_wrong_record_type_is_rejected(void)
{
    unsigned char p[160] = {0};
    write_client_hello_header(p);
    write_sni(p, 43, "example.com");
    p[0] = 0x17; // not a handshake record
    char out[96] = {0};
    assert(netra_l7_tls_sni(work(p, sizeof(p)), out) == 0);
}

static void tls_sni_within_scan_window_is_found(void)
{
    // The scan loop only inspects i in [43, 512); at i=500 it is still in
    // range, and the buffer is padded so the "would this name fit"
    // look-ahead check (i+9+95) doesn't bail out early.
    unsigned char p[620] = {0};
    write_client_hello_header(p);
    write_sni(p, 500, "example.com");
    char out[96] = {0};
    int n = netra_l7_tls_sni(work(p, sizeof(p)), out);
    assert(n == 11);
    assert(strcmp(out, "example.com") == 0);
}

static void tls_sni_past_scan_window_is_not_found(void)
{
    // i=512 is outside the scan loop's `i < 512` bound, so an SNI
    // extension placed there must never be found, even though the
    // buffer is large enough to hold it.
    unsigned char p[700] = {0};
    write_client_hello_header(p);
    write_sni(p, 512, "example.com");
    char out[96] = {0};
    assert(netra_l7_tls_sni(work(p, sizeof(p)), out) == 0);
}

static void tls_sni_invalid_candidate_keeps_searching(void)
{
    // A header-shaped match whose name holds a non-hostname byte is skipped,
    // and the real extension further on is still found.
    unsigned char p[300] = {0};
    write_client_hello_header(p);
    write_sni(p, 43, "bad name");
    write_sni(p, 120, "example.com");
    char out[96] = {0};
    int n = netra_l7_tls_sni(work(p, sizeof(p)), out);
    assert(n == 11);
    assert(strcmp(out, "example.com") == 0);
}

// ---- HTTP method/host ---------------------------------------------------

static void http_method_get(void)
{
    const char *req = "GET / HTTP/1.1\r\n";
    char out[8] = {0};
    int n = netra_l7_http_method((const unsigned char *)req, (int)strlen(req), out);
    assert(n == 3);
    assert(strcmp(out, "GET") == 0);
}

static void http_method_unrecognized_returns_zero(void)
{
    const char *req = "TRACE / HTTP/1.1\r\n";
    char out[8] = {0};
    assert(netra_l7_http_method((const unsigned char *)req, (int)strlen(req), out) == 0);
}

static void http_host_found(void)
{
    const char *req = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    char out[96] = {0};
    int n = netra_l7_http_host(work(req, strlen(req)), out);
    assert(n == 11);
    assert(strcmp(out, "example.com") == 0);
}

static void http_host_case_insensitive_header_name(void)
{
    const char *req = "GET / HTTP/1.1\r\nhOsT: example.com\r\n\r\n";
    char out[96] = {0};
    int n = netra_l7_http_host(work(req, strlen(req)), out);
    assert(n == 11);
    assert(strcmp(out, "example.com") == 0);
}

static void http_host_with_control_byte_is_rejected(void)
{
    // A control character inside the host value is outside the
    // printable-ASCII range the parser requires, so it must bail out
    // entirely (return 0) rather than emit a partial/garbled name.
    const char req[] = "GET / HTTP/1.1\r\nHost: exa\x01mple.com\r\n\r\n";
    char out[96] = {0};
    assert(netra_l7_http_host(work(req, sizeof(req) - 1), out) == 0);
}

static void http_host_missing_returns_zero(void)
{
    const char *req = "GET / HTTP/1.1\r\nAccept: */*\r\n\r\n";
    char out[96] = {0};
    assert(netra_l7_http_host(work(req, strlen(req)), out) == 0);
}

static void http_host_after_other_headers_with_whitespace(void)
{
    const char *req = "GET / HTTP/1.1\r\nAccept: */*\r\nX-Host: no\r\nHost:\t  Api.Example.com:8080\r\n\r\n";
    char out[96] = {0};
    int n = netra_l7_http_host(work(req, strlen(req)), out);
    assert(n == 20);
    assert(strcmp(out, "api.example.com:8080") == 0);
}

static void http_host_value_at_end_of_payload(void)
{
    const char *req = "GET / HTTP/1.1\r\nHost: example.com";
    char out[96] = {0};
    int n = netra_l7_http_host(work(req, strlen(req)), out);
    assert(n == 11);
    assert(strcmp(out, "example.com") == 0);
}

static void dns_qname_stops_at_compression_after_label(void)
{
    unsigned char p[12 + 1 + 3 + 2] = {0};
    p[12] = 3; memcpy(p + 13, "www", 3);
    p[16] = 0xC0; p[17] = 0x0C;
    char out[96] = {0};
    int n = netra_l7_dns_qname(work(p, sizeof(p)), out);
    assert(n == 3);
    assert(strcmp(out, "www") == 0);
}

static void http_status_ok(void)
{
    const char *resp = "HTTP/1.1 503 Service Unavailable\r\n";
    assert(netra_l7_http_status((void *)resp, (void *)(resp + strlen(resp))) == 503);
    const char *old = "HTTP/1.0 204\r\n";
    assert(netra_l7_http_status((void *)old, (void *)(old + strlen(old))) == 204);
}

static void http_status_http2_rejected(void)
{
    const char *resp = "HTTP/2 200\r\n";
    assert(netra_l7_http_status((void *)resp, (void *)(resp + strlen(resp))) == 0);
}

static void http_status_short_rejected(void)
{
    const char *resp = "HTTP/1.1";
    assert(netra_l7_http_status((void *)resp, (void *)(resp + strlen(resp))) == 0);
}

static void dns_qtype_complete_and_bounded(void)
{
    unsigned char p[] = {0,1,0x81,0x80,0,1,0,0,0,0,0,0,3,'w','w','w',0,0,16,0,1};
    assert(netra_l7_dns_qtype(work(p,sizeof(p))) == 16);
    for (size_t n=0;n<sizeof(p);n++) assert(netra_l7_dns_qtype(work(p,n))==0);
    p[18]=1;assert(netra_l7_dns_qtype(work(p,sizeof(p)))==1);
    p[5]=2;assert(netra_l7_dns_qtype(work(p,sizeof(p)))==0);p[5]=1;
    p[12]=0xc0;assert(netra_l7_dns_qtype(work(p,sizeof(p)))==0);p[12]=3;
    p[20]=3;assert(netra_l7_dns_qtype(work(p,sizeof(p)))==0);
    unsigned char longname[120]={0};longname[5]=1;longname[12]=63;memset(longname+13,'a',63);longname[76]=32;memset(longname+77,'b',32);
    longname[111]=16;longname[113]=1;
    assert(netra_l7_dns_qtype(work(longname,sizeof(longname)))==0);
}

int main(void)
{
    dns_qtype_complete_and_bounded();
    dns_qname_multi_label();
    dns_qname_uppercase_is_lowercased();
    dns_qname_truncated_mid_label();
    dns_qname_compression_pointer_is_rejected();
    dns_qname_empty_buffer();
    dns_qname_stops_at_compression_after_label();

    tls_sni_found();
    tls_sni_uppercase_is_lowercased();
    tls_sni_no_extension_present();
    tls_sni_wrong_record_type_is_rejected();
    tls_sni_within_scan_window_is_found();
    tls_sni_past_scan_window_is_not_found();
    tls_sni_invalid_candidate_keeps_searching();

    http_method_get();
    http_method_unrecognized_returns_zero();
    http_host_found();
    http_host_case_insensitive_header_name();
    http_host_with_control_byte_is_rejected();
    http_host_missing_returns_zero();
    http_host_after_other_headers_with_whitespace();
    http_host_value_at_end_of_payload();
    http_status_ok();
    http_status_http2_rejected();
    http_status_short_rejected();

    puts("netra l7 parsers: ok");
    return 0;
}
