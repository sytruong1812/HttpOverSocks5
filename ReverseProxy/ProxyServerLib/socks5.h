#pragma once
#include "socket.h"

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

	class Socks5Server
	{
	public:
        Socks5Server(const Endpoint& server_endpoint);
        Socks5Server(const std::string& server_addr, uint16_t server_port);
        Socks5Server(const Endpoint& server_endpoint, const std::string& username, const std::string& password);
        Socks5Server(const std::string& server_addr, uint16_t server_port, const std::string& username, const std::string& password);
        ~Socks5Server();
        bool Start();
        void Run();
        void Stop();
    private:
        void process_handle_client(SOCKET fd, const Endpoint& endpoint);
        bool process_server_greeting(PWSocket client);
        bool process_auth_handler(PWSocket client);
        bool process_connection_request(PWSocket client);
        bool send_reply(PWSocket client, const Endpoint& enpoint, REPLY reply);
        bool handle_tcp_connect(PWSocket client, const std::string& dest_addr, uint16_t dest_port);
        bool handle_udp_associate(PWSocket client, const std::string& dest_addr, uint16_t dest_port);
    private:
        bool _running;
        bool _enable_udp;
        bool _enable_auth;
        Endpoint _endpoint;
        std::string _auth_username;
        std::string _auth_password;
		std::unique_ptr<WSocket> _socket_tcp;
		std::unique_ptr<WSocket> _socket_udp;
	};
}