#include "reverse.h"

namespace NetworkOperations
{
    ReverseServer::ReverseServer(const Endpoint& serverEndpoint, const Endpoint& backendEndpoint)
    {
        _serverEndpoint = serverEndpoint;
        _backendEndpoint = backendEndpoint;
    }

    ReverseServer::ReverseServer(const std::string& serverAddress, uint16_t serverPort, const std::string& backendAddress, uint16_t backendPort)
    {
        _serverEndpoint = Endpoint::from_string(serverAddress.c_str(), serverPort);
        _backendEndpoint = Endpoint::from_string(backendAddress.c_str(), backendPort);
    }

    ReverseServer::~ReverseServer()
    {
        if (_running)
        {
            Stop();
        }
    }

    bool ReverseServer::Start()
    {		
        // step 1: Create TCP socket
        _serverSocket = std::make_shared<WSocket>(_serverEndpoint.address.family, WSocketTypes::TCP_STREAM);
        if (!_serverSocket)
        {
            LOG_ERROR_A("[-][Reverse Proxy] Could not create TCP socket!");
            return false;
        }
        // step 2: Bind TCP socket
        if (!_serverSocket->bind(_serverEndpoint))
        {
            LOG_ERROR_A("[-][Reverse Proxy] Failed to bind socket to %s", _serverEndpoint.to_string().c_str());
            _serverSocket->disconnect();
            return false;
        }
        // step 3: Listen for connections
        if (!_serverSocket->listen(SOMAXCONN))
        {
            LOG_ERROR_A("[-][Reverse Proxy] Listen on port %d failed!", _serverEndpoint.port);
            _serverSocket->disconnect();
            return false;
        }
        LOG_INFO_A("[+][Reverse Proxy] Server listening on %s", _serverEndpoint.to_string().c_str());
        _running = true;
        return true;
    }

    void ReverseServer::Run()
    {
        if (!_running || !_serverSocket)
        {
            return;
        }
        if (!_serverSocket->set_nonblocking(true))
        {
            return;
        }
        while (_running)
        {
            // Accept new connection
            Endpoint client_endpoint;
            auto client_socket = _serverSocket->accept(client_endpoint);
            // If a valid connection is returned
            if (client_socket != INVALID_SOCKET)
            {
                // Handle client in a new thread
                std::thread client_thread(&ReverseServer::process_handle_client, this, client_socket, client_endpoint);
                client_thread.detach();
            }
            else
            {
                std::error_code error = wsocket_get_last_error();
                if (error.value() != NO_ERROR && error.value() != WSAEWOULDBLOCK)
                {
                    LOG_ERROR_A("[-][Reverse Proxy] Accept error[%d]: %s", error.value(), error.message().c_str());
                }
            }
            // Small delay to prevent CPU hogging and avoid tight loop in non-blocking mode
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }

    void ReverseServer::Stop()
    {
        if (_serverSocket) {
            _serverSocket->disconnect();
        }
        if (_backendSocket) {
            _backendSocket->disconnect();
        }
        _running = false;
    }

    void ReverseServer::process_handle_client(SOCKET fd, const Endpoint& endpoint)
    {
        LOG_INFO_A("[+][Reverse Proxy] New client connected from %s", endpoint.to_string().c_str());
        auto client = std::make_shared<WSocket>(fd);

        char buffer[4096] = { 0 };
        int bytesReceived = client->tcp_recv_data(buffer, sizeof(buffer));
        if (bytesReceived <= 0)
        {
            return;
        }
        if (!forward_traffic(client.get(), buffer))
        {
            LOG_ERROR_A("[-][Reverse Proxy] Forwaring traffic to backend failed!");
            return;
        }
    }

    bool ReverseServer::forward_traffic(PWSocket client, const std::string& request)
    {        
        _backendSocket = std::make_shared<WSocket>(_backendEndpoint.address.family, WSocketTypes::TCP_STREAM);
        if (!_backendSocket)
        {
            LOG_ERROR_A("[-][Reverse Proxy] Could not create TCP socket for Backend Server!");
            return false;
        }
        if (_backendSocket->connect(_backendEndpoint))
        {
            if (_backendSocket->tcp_send_data(request.c_str(), (int)request.size()) < 0) 
            {
                _backendSocket->disconnect();
                return false;
            }
            char buffer[4096] = { 0 };
            int bytesRead = _backendSocket->tcp_recv_data(buffer, sizeof(buffer));
            if (bytesRead > 0)
            {
                if (client->tcp_send_data(buffer, bytesRead) < 0) {
                    _backendSocket->disconnect();
                    return false;
                }
            }
        }
        else 
        {
            LOG_ERROR_A("[-][Reverse Proxy] Could not connect to Backend Server.");
            return false;
        }
        _backendSocket->disconnect();
        return true;
    }
}