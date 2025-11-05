#pragma once
#include "socket.h"

#define SOCKS5_OK 1
#define SOCKS5_UNSUPORT -11
#define SOCKS5_ERROR_PARSE -12

#define ERROR_GREETING -21
#define ERROR_GSS_HANDLE -22
#define ERROR_AUTH_HANDLE -23
#define ERROR_CONNECTION_REQUEST -24

#ifdef ENABLE_GSSAPI
#ifndef SECURITY_WIN32
#define SECURITY_WIN32
#endif
#include <windows.h>
#include <sspi.h>
#include <string>
#pragma comment( lib, "Secur32.lib" )
#define ERROR_GSS_SIGN_MESSAGE -31
#define ERROR_GSS_VERIFY_MESSAGE -32
#define ERROR_GSS_ENCRYPT_MESSAGE -33
#define ERROR_GSS_DECRYPT_MESSAGE -34
#endif /* ENABLE_GSSAPI */

namespace NetworkOperations 
{
    enum class VERSION {
        ZERO = 0x00,
        SOCKS5 = 0x05
    };

    enum class METHODS {
        NO_AUTHENTICATION_REQUIRED = 0x00,
        GSS_API = 0x01,
        USERNAME_PASSWORD = 0x02,
        IANA_ASSIGNED = 0x03,
        RESERVED_FOR_PRIVATE_METHODS = 0x80,
        NO_ACCEPTABLE_METHODS = 0xFF,
    };

    enum class COMMAND {
        CONNECT = 0x01,
        BIND = 0x02,
        UDP_ASSOCIATE = 0x03
    };

    enum class ADDRESS_TYPE {
        IPV4 = 0x01,
        DOMAIN_NAME = 0x03,
        IPV6 = 0x04
    };
    enum class REPLY {
        SUCCEEDED = 0x00,
        GENERAL_SERVER_FAILURE = 0x01,
        CONNECTION_NOT_ALLOWED_BY_RULESET = 0x02,
        NETWORK_UNREACHABLE = 0x03,
        HOST_UNREACHABLE = 0x04,
        CONNECTION_REFUSED = 0x05,
        TTL_EXPIRED = 0x06,
        COMMAND_NOT_SUPPORTED = 0x06,
        ADDRESS_TYPE_NOT_SUPPORTED = 0x07,
        UNASSIGNED = 0x08
    };

#ifdef ENABLE_GSSAPI
    enum class GSS_MESSAGE_PROTECT_LEVEL 
    {
        LEVEL_1, // Required per-message integrity
        LEVEL_2, // Required per-message integrity and confidentiality
        LEVEL_3  // Selective per-message integrity or confidentiality based on local client and server configurations
    };
    struct GSS_CONTEXT
    {
        TimeStamp expiry_time;
        CredHandle cred_handle;
        CtxtHandle ctxt_handle;
        std::string target_spn;       // service@host = "http@server.example.com"
        std::string security_package; // default = "Kerberos"
        GSS_MESSAGE_PROTECT_LEVEL protect_level;
        ~GSS_CONTEXT()
        {
            if (ctxt_handle.dwLower || ctxt_handle.dwUpper)
            {
                DeleteSecurityContext(&ctxt_handle);
                ctxt_handle = {};
            }
            if (cred_handle.dwLower || cred_handle.dwUpper)
            {
                FreeCredentialsHandle(&cred_handle);
                cred_handle = {};
            }
        }
    };
#endif /* ENABLE_GSSAPI */

    enum class SOCKS5_RESOLVE 
    {
        LOCAL_RESOLVE,
        REMOTE_RESOLVE
    };

    class Socks5Client : public ITransport 
    {
    public:
        /// <summary>
        /// Constructs a Socks5Client object with the proxy server address and port.
        /// </summary>
        /// <param name="server_addr:">IP address or hostname of the SOCKS5 proxy server.</param>
        /// <param name="server_port:">Port number to connect to the SOCKS5 proxy server.</param>
        /// <param name="type:">Socket type (TCP_STREAM or UDP_DATAGRAM). Default is TCP_STREAM.</param>
        /// <param name="enable_ipv6:">Enable IPv6 if true, otherwise IPv4. Default is false.</param>
        /// <param name="resolve:">Hostname resolution mode:
        /// LOCAL_RESOLVE: resolve hostname locally on the client.
        /// REMOTE_RESOLVE: resolve hostname on the proxy server.
        /// Default is LOCAL_RESOLVE.
        /// </param>
        Socks5Client(const char* server_addr, int server_port,
            SOCKET_TYPES type = SOCKET_TYPES::TCP_STREAM, bool enable_ipv6 = false,
            SOCKS5_RESOLVE resolve = SOCKS5_RESOLVE::LOCAL_RESOLVE);

        /// <summary>
        /// Constructs a Socks5Client object with the proxy server address, port, and authentication credentials.
        /// </summary>
        /// <param name="server_addr:">IP address or hostname of the SOCKS5 proxy server.</param>
        /// <param name="server_port:">Port number to connect to the SOCKS5 proxy server.</param>
        /// <param name="username:">Username for authenticating with the proxy server.</param>
        /// <param name="password:">Password for authenticating with the proxy server.</param>
        /// <param name="type:">Socket type (TCP_STREAM or UDP_DATAGRAM). Default is TCP_STREAM.</param>
        /// <param name="enable_ipv6:">Enable IPv6 if true, otherwise IPv4. Default is false.</param>
        /// <param name="resolve:">Hostname resolution mode:
        /// LOCAL_RESOLVE: resolve hostname locally on the client.
        /// REMOTE_RESOLVE: resolve hostname on the proxy server.
        /// Default is LOCAL_RESOLVE.
        /// </param>
        Socks5Client(const char* server_addr, int server_port,
            const char* username, const char* password,
            SOCKET_TYPES type = SOCKET_TYPES::TCP_STREAM, bool enable_ipv6 = false,
            SOCKS5_RESOLVE resolve = SOCKS5_RESOLVE::LOCAL_RESOLVE);

#ifdef ENABLE_GSSAPI
        /// <summary>
        /// Constructs a Socks5Client object with GSSAPI security parameters.
        /// </summary>
        /// <param name="server_addr:">IP address or hostname of the SOCKS5 proxy server.</param>
        /// <param name="server_port:">Port number to connect to the SOCKS5 proxy server.</param>
        /// <param name="service:">The service type "http".</param>
        /// <param name="hostname:">The hostname, (e.g "server.example.com)".</param>
        /// <param name="security:">The security mechanism to use, default is "Kerberos".</param>
        /// <param name="type:">Socket type (TCP_STREAM or UDP_DATAGRAM). Default is TCP_STREAM.</param>
        /// <param name="enable_ipv6:">Enable IPv6 if true, otherwise IPv4. Default is false.</param>
        /// <param name="resolve:">Hostname resolution mode:
        /// LOCAL_RESOLVE: resolve hostname locally on the client.
        /// REMOTE_RESOLVE: resolve hostname on the proxy server.
        /// Default is LOCAL_RESOLVE.
        /// </param>
        Socks5Client(const char* server_addr, int server_port,
            const char* service, const char* hostname, const char* security,
            SOCKET_TYPES type = SOCKET_TYPES::TCP_STREAM, bool enable_ipv6 = false,
            SOCKS5_RESOLVE resolve = SOCKS5_RESOLVE::LOCAL_RESOLVE);
#endif /* ENABLE_GSSAPI */

        ~Socks5Client() override;
        void* get_socket() const override;
        int connect(const char* dst_addr, int dst_port) override;
        int tcp_send_data(const char* data, int len) override;
        int tcp_recv_data(char* data, int len) override;
        int tcp_send_timeout(const char* data, int len, unsigned int time_msec) override;
        int tcp_recv_timeout(char* data, int len, unsigned int time_msec) override;
        int tcp_send_data_select_based(const char* data, int len) override;
        int tcp_recv_data_select_based(char* data, int len) override;
        int udp_send_to(const char* dest_addr, int dest_port, const char* data, int len) override;
        int udp_recv_from(char** sender_addr, int* sender_port, char* data, int len) override;
        void shutdown(int how) override;
        void disconnect() override;
    private:
        int client_greeting();
        int client_gss_handler();
        int client_auth_handler();
        int client_connection_request(char** bnd_addr, int* bnd_port);
#ifdef ENABLE_GSSAPI
        bool gss_auth_is_gssapi_supported(const void* security_package);
        int gss_make_signature(const void* data, int data_size, void** sign, int* sign_size);
        int gss_verify_signature(const void* data, int data_size, const void* sign, int sign_size);
        int gss_encrypt_message(const void* data_in, int data_in_size, void** data_out, int* data_out_size);
        int gss_decrypt_message(const void* data_in, int data_in_size, void** data_out, int* data_out_size);
#endif /* ENABLE_GSSAPI */
    private:
        bool _is_ipv6 = false;
        bool _is_connected = false;
        METHODS _auth_type;
        SOCKET_TYPES _type;
        SOCKS5_RESOLVE _resolve;
#ifdef ENABLE_GSSAPI
        std::shared_ptr<GSS_CONTEXT> _gss;
#endif /* ENABLE_GSSAPI */
        std::shared_ptr<WSocket> _socket_tcp;
        std::shared_ptr<WSocket> _socket_udp;
        char* _socks5_serv_addr = nullptr; int _socks5_serv_port = 0;
        char* _socks5_username = nullptr; char* _socks5_password = nullptr;
        char* _destination_addr = nullptr; int _destination_port = 0;
        char* _bound_addr = nullptr; int _bound_port = 0;
    };
}
