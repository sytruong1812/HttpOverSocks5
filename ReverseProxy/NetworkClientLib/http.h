#pragma once
#include "chunk.h"
#include "socks5.h"
#include "request.h"
#include "response.h"

namespace NetworkOperations 
{
    class HttpClient 
    {
    public:
        HttpClient() = default;
        ~HttpClient();
        bool Connect(const std::string& host, int port);
        bool ConnectViaSocks5(const std::string& host, int port,
            const std::string& proxy_host, int proxy_port);
        bool ConnectViaSocks5Auth(const std::string& host, int port,
            const std::string& proxy_host, int proxy_port,
            const std::string& proxy_username, const std::string& proxy_password);
        bool IsConnected() { return _is_connected; }
        std::unique_ptr<Response> SendRequest(const std::unique_ptr<Request>& request);
        std::unique_ptr<Response> Get(const std::string& path, const Headers& header);
        std::unique_ptr<Response> Post(const std::string& path, const Headers& header, const std::string& body);
        bool UploadFile(const std::string& path, const Headers& header, const std::wstring& input_path);
        bool DownloadFile(const std::string& path, const Headers& header, const std::wstring& output_path);
        void Disconnect();
    private:
        bool ProcessSendRequest(const std::unique_ptr<Request>& request);
        bool ProcessReadResponse(std::unique_ptr<Response>& response);
        bool ProcessReadHeaderResponse(PBYTE& header_data, DWORD& header_size);
        bool ProcessReadContentResponse(PBYTE& content_data, DWORD& content_size);
    private:
        bool _is_connected = false;
        uint16_t _port = 8080;
        std::string _host = "localhost";
        std::shared_ptr<ITransport> _transport;
    };
}
