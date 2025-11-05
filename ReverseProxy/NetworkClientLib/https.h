#pragma once
#include "tls.h"
#include "http.h"

namespace NetworkOperations
{
    class HttpsClient
    {
    public:
        /// <summary>
        /// Default constructor.
        /// Use when no certificate is needed or SSL configuration will be done later
        /// </summary>
        HttpsClient();
        /// <summary>
        /// Constructor with CA certificate.
        /// Used to verify the server's identity during HTTPS connections.
        /// </summary>
        /// <param name="cert_path:">Path to the trusted CA certificate file (.pfx).</param>
        HttpsClient(const std::string& cert_path);
        /// <summary>
        /// Constructor with CA certificate.
        /// Used to verify the server's identity during HTTPS connections..
        /// </summary>
        /// <param name="cert_path:">Path to the trusted CA certificate file using import to store (.pfx).</param>
        /// <param name="password:">String password used to decrypt and verify the PFX packet.</param>
        /// <param name="subject_name:">Specified subject name string.</param>
        HttpsClient(const std::string& cert_path, const std::string& password, const std::string& subject_name);

        ~HttpsClient();
        bool Connect(const std::string& host, int port);
        bool ConnectViaSocks5(const std::string& host, int port,
            const std::string& proxy_host, int proxy_port);
        bool ConnectViaSocks5Auth(const std::string& host, int port,
            const std::string& proxy_host, int proxy_port,
            const std::string& proxy_username, const std::string& proxy_password);
        bool IsConnected() { return _is_connected; }
        bool IsHandshake() { return _is_handshake; }
        std::unique_ptr<Response> SendRequest(const std::unique_ptr<Request>& request);
        std::unique_ptr<Response> Get(const std::string& path, const Headers& header);
        std::unique_ptr<Response> Post(const std::string& path, const Headers& header, const std::string& body);
        bool UploadFile(const std::string& path, const Headers& header, const std::wstring& input_path);
        bool DownloadFile(const std::string& path, const Headers& header, const std::wstring& output_path);
        void Disconnect();
    private:

    private:
        bool _is_connected = false;
        bool _is_handshake = false;
        uint16_t _port = 8443;
        std::string _host = "localhost";
        std::shared_ptr<ISecurity> _security;
        std::shared_ptr<ITransport> _transport;
    };
}


