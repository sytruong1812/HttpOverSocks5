#pragma once
#ifndef WIN32_LEAN_AND_MEAN
#	define WIN32_LEAN_AND_MEAN
#endif
#include <mutex>
#include <windows.h>
#include <schannel.h>
#ifndef SECURITY_WIN32
#   define SECURITY_WIN32
#endif
#include <security.h>
#pragma comment(lib, "secur32.lib" )
#include <wincrypt.h>
#pragma comment(lib, "crypt32.lib")

#include "socket.h"

#define TLS_MAX_RECORD_SIZE (16 * 1024)                  // TLS defines records to be up to 16kb.
#define TLS_MAX_PACKET_SIZE (TLS_MAX_RECORD_SIZE + 512)  // Payload + Extra over head for header/mac/padding (probably an overestimate)

namespace NetworkOperations
{
    class SchannelTLS
    {
    public:
        static CredHandle get_schannel_server_handle(PCCERT_CONTEXT cert_ctx);
        static CredHandle get_schannel_client_handle(PCCERT_CONTEXT cert_ctx);

        static void free_cred_handle(CredHandle cred_handle);
        static void free_ctxt_handle(CtxtHandle ctxt_handle);

        static CtxtHandle server_perform_handshake(CredHandle cred_handle, PWSocket transport);
        static CtxtHandle client_perform_handshake(CredHandle cred_handle, PWSocket transport, const char* host_name, bool verify_server_cert);

        static bool shutdown(CredHandle cred_handle, CtxtHandle ctxt_handle, PWSocket transport);

        static int tls_read_data(CtxtHandle ctxt_handle, PWSocket transport, char* data, int len);
        static int tls_write_data(CtxtHandle ctxt_handle, PWSocket transport, const char* data, int len);
       
        static SecPkgContext_StreamSizes get_stream_sizes(CtxtHandle ctxt_handle);
        static int encrypt_data(CtxtHandle security_context, SecPkgContext_StreamSizes stream_sizes, const void* in_buf, int in_len, void* out_buf, int out_len);
        static int decrypt_data(CtxtHandle security_context, SecPkgContext_StreamSizes stream_sizes, const void* in_buf, int in_len, void* out_buf, int out_len);
    };
}