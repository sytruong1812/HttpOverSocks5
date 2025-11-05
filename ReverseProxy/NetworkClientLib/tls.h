#pragma once
#include "socket.h"
#include "socks5.h"

#ifndef ENABLE_SCHANNEL
#   define ENABLE_SCHANNEL
#endif

#ifdef ENABLE_SCHANNEL
#ifndef WIN32_LEAN_AND_MEAN
#	define WIN32_LEAN_AND_MEAN
#endif
#include <mutex>
#include <windows.h>
#include <schannel.h>
#ifndef SECURITY_WIN32
    #define SECURITY_WIN32
#endif
#include <security.h>
#pragma comment(lib, "secur32.lib" )
#include <wincrypt.h>
#pragma comment(lib, "crypt32.lib")

#define TLS_MAX_RECORD_SIZE (16 * 1024)                  // TLS defines records to be up to 16kb.
#define TLS_MAX_PACKET_SIZE (TLS_MAX_RECORD_SIZE + 512)  // Payload + Extra over head for header/mac/padding (probably an overestimate)

#elif defined(ENABLE_MBEDTLS)
#include "mbedtls/ssl.h"
#include "mbedtls/debug.h"
#include "mbedtls/error.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/x509.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/platform.h"

#define MBEDTLS_DEBUG_LEVEL 3

#elif defined(ENABLE_WOLFSSL)
// TODO: Include WolfSSL header 
#else

#endif

namespace NetworkOperations 
{
    class ISecurity 
    {
    public:
        virtual ~ISecurity() = default;
        virtual bool set_trusted_ca(const char* cert_path, const char* password, const char* subject_name) = 0;
        virtual bool initialize(void* ctx) = 0;
        virtual bool perform_handshake(const char* host_name, bool verify_server_cert) = 0;
        virtual int read_data(char* data, int len) = 0;
        virtual int write_data(const char* data, int len) = 0;
        virtual bool shutdown() = 0;
    };

#if defined(ENABLE_SCHANNEL)

class SchannelTLS : public ISecurity
{
public:
    SchannelTLS();
    ~SchannelTLS() override;
    bool set_trusted_ca(const char* cert_path, const char* password, const char* subject_name) override;
    bool initialize(void* ctx) override;
    bool perform_handshake(const char* host_name, bool verify_server_cert) override;
    int read_data(char* data, int len) override;
    int write_data(const char* data, int len) override;
    bool shutdown() override;
private:
    bool establish_client_security_context_first_stage(const char* host_name);
    bool establish_client_security_context_second_stage(const char* host_name, bool verify_server_cert);
    static SecPkgContext_StreamSizes get_stream_sizes(CtxtHandle security_context);
    static int encrypt_data(CtxtHandle security_context, SecPkgContext_StreamSizes stream_sizes, const void* in_buf, int in_len, void* out_buf, int out_len);
    static int decrypt_data(CtxtHandle security_context, SecPkgContext_StreamSizes stream_sizes, const void* in_buf, int in_len, void* out_buf, int out_len);
    static void init_sec_buffer_desc(SecBufferDesc& secure_buffer_desc, unsigned long version, unsigned long num_buffers, SecBuffer* buffers);
    static void init_sec_buffer(SecBuffer& secure_buffer, unsigned long type, unsigned long len, void* buffer);
    static void free_all_buffers(SecBufferDesc& secure_buffer_desc);
private:
    CredHandle _handle;
    CtxtHandle _context;
    ITransport* _transport;
    PCCERT_CONTEXT _cert_ctx;
private:    
    char incoming[TLS_MAX_PACKET_SIZE] = { 0 };
};

#elif defined(ENABLE_MBEDTLS)
    class MbedTLS : public ISecurity
    {
    public:
        MbedTLS();
        ~MbedTLS() override;
        bool set_trusted_ca(const char* cert_path, const char* password, const char* subject_name) override;
        bool initialize(void* ctx) override;
        bool perform_handshake(const char* host_name, bool verify_server_cert) override;
        int read_data(char* data, int len) override;
        int write_data(const char* data, int len) override;
        bool shutdown() override;
    private:
        static int transport_recv(void* ctx, unsigned char* buf, size_t len);
        static int transport_send(void* ctx, const unsigned char* buf, size_t len);
        static void debug_printf(void* ctx, int level, const char* file, int line, const char* str);
    private:
        mbedtls_ssl_context _ssl;
        mbedtls_ssl_config _conf;
        mbedtls_ctr_drbg_context _ctr_drbg;
        mbedtls_entropy_context _entropy;
        mbedtls_x509_crt _cacert;
        mbedtls_pk_context _pkey;
    };

#elif defined(ENABLE_WOLFSSL)
    class WolfSSL : public ISecurity
    {
    public:
    private:
    };
#else

#endif

} /* NetworkOperations */