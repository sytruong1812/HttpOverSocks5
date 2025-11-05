#include "socks5.h"
#include "utils.h"

namespace NetworkOperations
{
	Socks5Server::Socks5Server(const Endpoint& server_endpoint)
	{
		_running = false;
		_enable_udp = false;
		_enable_auth = false;
		_endpoint = server_endpoint;
	}
	Socks5Server::Socks5Server(const std::string& server_addr, uint16_t server_port)
	{
		_running = false;
		_enable_udp = false;
		_enable_auth = false;
		_endpoint = Endpoint::from_string(server_addr.c_str(), server_port);
	}
	Socks5Server::Socks5Server(const Endpoint& server_endpoint, const std::string& username, const std::string& password)
	{
		_running = false;
		_enable_udp = false;
		_enable_auth = false;
		_endpoint = server_endpoint;
		if (!username.empty() && !password.empty())
		{
			_enable_auth = true;
			_auth_username = username;
			_auth_password = password;
		}
	}
	Socks5Server::Socks5Server(const std::string& server_addr, uint16_t server_port, const std::string& username, const std::string& password)
	{
		_running = false;
		_enable_udp = false;
		_enable_auth = false;
		_endpoint = Endpoint::from_string(server_addr.c_str(), server_port);
		if (!username.empty() && !password.empty())
		{
			_enable_auth = true;
			_auth_username = username;
			_auth_password = password;
		}
	}
	Socks5Server::~Socks5Server()
	{
		if (_running) 
		{
			Stop();
		}
	}
	bool Socks5Server::Start()
	{	
		// step 1: Create TCP socket
		_socket_tcp = std::make_unique<WSocket>(_endpoint.address.family, WSocketTypes::TCP_STREAM);
		if (!_socket_tcp) 
		{
			LOG_ERROR_A("[-][Socks5] Could not create TCP socket!");
			return false;
		}
		// step 2: Bind TCP socket
		if (!_socket_tcp->bind(_endpoint)) 
		{
			LOG_ERROR_A("[-][Socks5] Failed to bind socket to %s", _endpoint.to_string().c_str());
			//_socket_tcp->disconnect();
			return false;
		}
		// step 3: Listen for connections
		if (!_socket_tcp->listen(SOMAXCONN))
		{
			LOG_ERROR_A("[-][Socks5] Listen on port %d failed!", _endpoint.port);
			//_socket_tcp->disconnect();
			return false;
		}
		LOG_INFO_A("[+][Socks5] Server listening on %s", _endpoint.to_string().c_str());

		if (_enable_udp) 
		{
			// step 4: Create UDP socket
			_socket_udp = std::make_unique<WSocket>(_endpoint.address.family, WSocketTypes::UDP_DATAGRAM);
			if (!_socket_udp)
			{
				LOG_ERROR_A("[-][Socks5] Could not create UDP socket!");
				return false;
			}
			// step 5: Bind UDP socket
			if (!_socket_udp->bind(_endpoint)) 
			{
				LOG_ERROR_A("[-][Socks5] Failed to bind socket to %s", _endpoint.to_string().c_str());
				//_socket_udp->disconnect();
				return false;
			}

			//TODO: Handling...

			LOG_INFO_A("[+][Socks5] UDP relay started.");
		}

		_running = true;
		return true;
	}
	
	void Socks5Server::Run()
	{
		if (!_socket_tcp || !_running)
		{
			return;
		}
		// Set non-blocking mode
		if (!_socket_tcp->set_nonblocking(true))
		{
			return;
		}
		while (_running)
		{
			// Accept new connection
			Endpoint client_endpoint;
			auto client_socket = _socket_tcp->accept(client_endpoint);

			// If a valid connection is returned
			if (client_socket != INVALID_SOCKET)
			{
				// Handle client in a new thread
				std::thread client_thread(&Socks5Server::process_handle_client, this, client_socket, client_endpoint);
				client_thread.detach();
			}
			else
			{
				std::error_code error = wsocket_get_last_error();
				if (error.value() != NO_ERROR && error.value() != WSAEWOULDBLOCK)
				{
					LOG_ERROR_A("[-][Socks5] Accept error[%d]: %s", error.value(), error.message().c_str());
				}
			}
			// Small delay to prevent CPU hogging and avoid tight loop in non-blocking mode
			std::this_thread::sleep_for(std::chrono::milliseconds(1));
		}
	}

	void Socks5Server::Stop()
	{
		if (_socket_udp) {
			_socket_udp->disconnect();
		}
		if (_socket_tcp) {
			_socket_tcp->shutdown();
			_socket_tcp->disconnect();
		}
		_running = false;
	}
	void Socks5Server::process_handle_client(SOCKET fd, const Endpoint& endpoint)
	{
		LOG_INFO_A("[+][Socks5] New client connected from %s", endpoint.to_string().c_str());
		auto client = std::make_shared<WSocket>(fd);

		// Set socket to blocking mode for handshake
		client->set_nonblocking(false);
		// Set receive timeout
		client->set_recv_timeout(60 * 1000);

		if (!process_server_greeting(client.get()))
		{
			LOG_ERROR_A("[-][Socks5] Process server greeting failed!");
			return;
		}
		if (!process_auth_handler(client.get()))
		{
			LOG_ERROR_A("[-][Socks5] Process auth handler failed!");
			return;
		}
		if (!process_connection_request(client.get()))
		{
			LOG_ERROR_A("[-][Socks5] Process Connection Request failed!");
			return;
		}
	}
	bool Socks5Server::process_server_greeting(PWSocket client)
	{
		// Read auth method request
		char client_greeting_msg[257]; // Max 255 methods + version + nmethods
		int bytesRead = client->tcp_recv_data(client_greeting_msg, 2);
		if (bytesRead < 0)
		{
			LOG_ERROR_A("[-][Socks5] Failed to read auth method request!");
			return false;
		}
		/*
		The client connects to the server, and sends a version identifier/method selection message:
			+----+----------+----------+
			|VER | NMETHODS | METHODS  |
			+----+----------+----------+
			| 1  |    1     | 1 to 255 |
			+----+----------+----------+
		*/
		uint8_t ver = client_greeting_msg[0];
		if (ver != static_cast<char>(VERSION::SOCKS5))
		{
			LOG_ERROR_A("[-][Socks5] Unsupported SOCKS version: %d", (int)ver);
			return false;
		}
		// Read auth methods
		uint8_t nmethods = client_greeting_msg[1];
		bytesRead = client->tcp_recv_data(client_greeting_msg + 2, nmethods);
		if (bytesRead != nmethods)
		{
			LOG_ERROR_A("[-][Socks5] Failed to read auth methods!");
			return false;
		}
		LOG_INFO_A("[+][Socks5] Auth negotiation: version=%d, nmethods=%d", (int)ver, (int)nmethods);
		
		// Select auth method
		uint8_t selected_method = static_cast<uint8_t>(METHODS::NO_ACCEPTABLE_METHODS);
		if (_enable_auth)
		{
			// Check if username/password auth is supported
			for (int i = 0; i < nmethods; i++)
			{
				if (client_greeting_msg[i + 2] == static_cast<uint8_t>(METHODS::USERNAME_PASSWORD))
				{
					selected_method = static_cast<uint8_t>(METHODS::USERNAME_PASSWORD);
					break;
				}
			}
		}
		else
		{
			// Check if no auth is supported
			for (int i = 0; i < nmethods; i++)
			{
				if (client_greeting_msg[i + 2] == static_cast<uint8_t>(METHODS::NO_AUTHENTICATION_REQUIRED))
				{
					selected_method = static_cast<uint8_t>(METHODS::NO_AUTHENTICATION_REQUIRED);
					break;
				}
			}
		}
		/*
		The SOCKS handshake method response is formed as follows:
            +----+--------+
            |VER | METHOD |
            +----+--------+
            | 1  |   1    |
            +----+--------+
		*/
		char server_choice[2];
		server_choice[0] = static_cast<char>(VERSION::SOCKS5);
		server_choice[1] = selected_method;

		// Send auth method response
		int bytesSent = client->tcp_send_data(server_choice, 2);
		if (bytesSent != 2)
		{
			LOG_ERROR_A("[-][Socks5] Failed to send auth method response!");
			return false;
		}
		// If no acceptable method, return false
		if (selected_method == static_cast<uint8_t>(METHODS::NO_ACCEPTABLE_METHODS))
		{
			LOG_ERROR_A("[-][Socks5] No acceptable method.");
			return false;
		}
		return true;
	}
	bool Socks5Server::process_auth_handler(PWSocket client)
	{
		if (_enable_auth)
		{
			/*
			Request: This begins with the client producing a Username/Password request:
				+----+------+----------+------+----------+
				|VER | ULEN |  UNAME   | PLEN |  PASSWD  |
				+----+------+----------+------+----------+
				| 1  |  1   | 1 to 255 |  1   | 1 to 255 |
				+----+------+----------+------+----------+
			*/
			char buf[1]; // Version of the Subnegotiation
			if (client->tcp_recv_data(buf, 1) < 0)
			{
				return false;
			}
			if (buf[0] != 0x01)
			{
				LOG_ERROR_A("[-] Unsupported version of the subnegotiation: %d", (int)buf[0]);
				return false;
			}
			client->tcp_recv_data(buf, 1);
			unsigned char ulen = (unsigned char)buf[0];
			std::vector<char> uname(ulen);
			client->tcp_recv_data(uname.data(), ulen);

			client->tcp_recv_data(buf, 1);
			unsigned char plen = (unsigned char)buf[0];
			std::vector<char> passwd(plen);
			client->tcp_recv_data(passwd.data(), plen);

			// Check Username/Password
			char answer[2];
			answer[0] = 0x01;
			answer[1] = 0x01;
			/*
			Response: The server verifies the supplied UNAME and PASSWD, and sends the following response:
				+----+--------+
				|VER | STATUS |
				+----+--------+
				| 1  |   1    |
				+----+--------+
			*/
			if ((strncmp(uname.data(), _auth_username.c_str(), _auth_username.length()) == 0) 
			&& (strncmp(passwd.data(), _auth_password.c_str(), _auth_password.length()) == 0))
			{
				answer[1] = 0x00;
			}
			if (client->tcp_send_data(answer, 2) < 0) 
			{
				return false;
			}
		}
		return true;
	}
	bool Socks5Server::process_connection_request(PWSocket client)
	{
		// Read request
		char buffer[262]; // Max domain name length + fixed fields
		int bytes_read = client->tcp_recv_data(buffer, 4);
		if (bytes_read != 4)
		{
			LOG_ERROR_A("[-][Socks5] Failed to read Connection Request data!");
			return false;
		}
		/*
		The SOCKS request is formed as follows:
			+----+-----+-------+------+----------+----------+
			|VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
			+----+-----+-------+------+----------+----------+
			| 1  |  1  | X'00' |  1   | Variable |    2     |
			+----+-----+-------+------+----------+----------+
		*/
		if (buffer[0] != static_cast<char>(VERSION::SOCKS5))
		{
			LOG_ERROR_A("[-][Socks5] Unsupported SOCKS version: %d", (int)buffer[0]);
			return false;
		}
		// Get command
		uint8_t cmd = buffer[1];
		// Get address type
		uint8_t atyp = buffer[3];
		// Read address and port
		uint16_t dest_port = 0;
		std::string dest_address;
		if (atyp == static_cast<uint8_t>(ADDRESS_TYPE::IPV4))
		{
			// IPv4 address
			bytes_read = client->tcp_recv_data(buffer + 4, 6);
			if (bytes_read != 6)
			{
				LOG_ERROR_A("[-][Socks5] Failed to read IPv4 address and port!");
				return false;
			}
			char ipv4[INET_ADDRSTRLEN];
			inet_ntop(AF_INET, buffer + 4, ipv4, INET_ADDRSTRLEN);
			dest_address = ipv4;
			dest_port = ((uint8_t)(buffer[8]) << 8) | (uint8_t)(buffer[9]);
		}
		else if (atyp == static_cast<uint8_t>(ADDRESS_TYPE::DOMAIN_NAME))
		{
			// Domain name
			bytes_read = client->tcp_recv_data(buffer + 4, 1);
			if (bytes_read != 1)
			{
				LOG_ERROR_A("[-][Socks5] Failed to read domain name length!");
				return false;
			}
			uint8_t domain_len = buffer[4];
			bytes_read = client->tcp_recv_data(buffer + 5, domain_len + 2);
			if (bytes_read != domain_len + 2)
			{
				LOG_ERROR_A("[-][Socks5] Failed to read domain name and port!");
				return false;
			}
			dest_address = std::string((char*)buffer + 5, domain_len);
			dest_port = ((uint8_t)(buffer[5 + domain_len]) << 8) | (uint8_t)(buffer[5 + domain_len + 1]);
		}
		else if (atyp == static_cast<uint8_t>(ADDRESS_TYPE::IPV6))
		{
			// IPv6 address
			bytes_read = client->tcp_recv_data(buffer + 4, 18);
			if (bytes_read != 18)
			{
				LOG_ERROR_A("[-][Socks5] Failed to read IPv6 address and port!");
				return false;
			}
			char ipv6[INET6_ADDRSTRLEN];
			inet_ntop(AF_INET6, buffer + 4, ipv6, INET6_ADDRSTRLEN);
			dest_address = ipv6;
			dest_port = ((uint8_t)(buffer[20]) << 8) | (uint8_t)(buffer[21]);
		}
		else
		{
			LOG_ERROR_A("[-][Socks5] Unsupported address type: %d", (int)atyp);
			send_reply(client, Endpoint(), REPLY::ADDRESS_TYPE_NOT_SUPPORTED);
			return false;
		}
		LOG_INFO_A("[+][Socks5] Request: %s %s:%d", 
			(cmd == static_cast<uint8_t>(COMMAND::CONNECT) ? "CONNECT"
			: cmd == static_cast<uint8_t>(COMMAND::BIND) ? "BIND"
			: cmd == static_cast<uint8_t>(COMMAND::UDP_ASSOCIATE) ? "UDP ASSOCIATE"
			: "UNKNOWN"), 
			dest_address.c_str(), dest_port);

		// Process command
		if (cmd == static_cast<uint8_t>(COMMAND::CONNECT))
		{
			LOG_INFO_A("[+][Socks5] On handle TCP connection...");
			if (!handle_tcp_connect(client, dest_address, dest_port))
			{
				LOG_ERROR_A("[-][Socks5] Failed to handle TCP connection!");
				return false;
			}
		}
		else if (cmd == static_cast<uint8_t>(COMMAND::UDP_ASSOCIATE))
		{
			LOG_INFO_A("[+][Socks5] On handle UDP associate...");
			if (!handle_udp_associate(client, dest_address, dest_port))
			{
				LOG_ERROR_A("[-][Socks5] Failed to handle UDP associate!");
				return false;
			}
		}
		else
		{
			LOG_ERROR_A("[-][Socks5] Unsupported command: %d", (int)cmd);
			send_reply(client, Endpoint(), REPLY::COMMAND_NOT_SUPPORTED);
			return false;
		}
		return true;
	}
	bool Socks5Server::send_reply(PWSocket client, const Endpoint& enpoint, REPLY reply)
	{
		/*
		The server evaluates the request, and returns a reply formed as follows:
			+----+-----+-------+------+----------+----------+
			|VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
			+----+-----+-------+------+----------+----------+
			| 1  |  1  | X'00' |  1   | Variable |    2     |
			+----+-----+-------+------+----------+----------+
		*/
		std::vector<char> server_reply_msg;
		server_reply_msg.push_back(static_cast<char>(VERSION::SOCKS5));
		server_reply_msg.push_back(static_cast<char>(reply));
		server_reply_msg.push_back(0);	// Reserved

		if (enpoint.address.is_ipv4())
		{
			// Copy IPv4 address
			server_reply_msg.push_back(static_cast<char>(ADDRESS_TYPE::IPV4));
			const uint8_t* ipv4 = enpoint.address.get_ipv4_bytes();
			server_reply_msg.insert(server_reply_msg.end(), ipv4, ipv4 + 4);
		}
		else
		{
			// Copy IPv6 address
			server_reply_msg.push_back(static_cast<char>(ADDRESS_TYPE::IPV6));
			const uint8_t* ipv6 = enpoint.address.get_ipv6_bytes();
			server_reply_msg.insert(server_reply_msg.end(), ipv6, ipv6 + 16);
		}
		// Copy port
		server_reply_msg.push_back(static_cast<char>((int)(enpoint.port) >> 8));
		server_reply_msg.push_back(static_cast<char>((int)enpoint.port));

		if (client->tcp_send_data(server_reply_msg.data(), (int)server_reply_msg.size()) < 0) 
		{
			return false;
		}
		return true;
	}
	
	bool Socks5Server::handle_tcp_connect(PWSocket client, const std::string& dest_addr, uint16_t dest_port)
	{
		// Resolve destination address
		auto destAddrs = dns_resolve_hostname(dest_addr.c_str());
		if (destAddrs.empty())
		{
			LOG_ERROR_A("[-][Socks5] Failed to resolve destination address: %s", dest_addr.c_str());
			send_reply(client, Endpoint(), REPLY::HOST_UNREACHABLE);
			return false;
		}

		// Try to connect to destination
		Endpoint destEndpoint;
		auto destSocket = std::make_shared<WSocket>(AddressFamily::IPv4, WSocketTypes::TCP_STREAM);
		for (const auto& addr : destAddrs)
		{
			destEndpoint.address = addr;
			destEndpoint.port = dest_port;
			if (!destSocket->connect(destEndpoint))
			{
				destSocket->disconnect();
			}
			break;
		}
		if (!destSocket->is_connected())
		{
			LOG_ERROR_A("[-][Socks5] Failed to connect to destination: %s:%d ", dest_addr.c_str(), dest_port);
			send_reply(client, Endpoint(), REPLY::CONNECTION_REFUSED);
			return false;
		}
		// Send success reply
		if (!send_reply(client, Endpoint(), REPLY::SUCCEEDED))
		{
			LOG_ERROR_A("[-][Socks5] Failed to send a SUCCEEDED reply!");
			return false;
		}

		// Set non-blocking mode
		client->set_nonblocking(true);
		destSocket->set_nonblocking(true);
		// Set socket timeout
		destSocket->set_recv_timeout(60 * 1000);	
		
		// Start data transfer
		std::vector<char> clientBuffer(8192);
		std::vector<char> destBuffer(8192);

		bool clientClosed = false;
		bool destClosed = false;

		while (!clientClosed && !destClosed)
		{
			// Check for data from client
			if (!clientClosed)
			{
				int bytesRead = client->tcp_recv_data(clientBuffer.data(), (int)clientBuffer.size());
				if (bytesRead > 0)
				{
					// Forward data to destination
					int bytesSent = destSocket->tcp_send_data(clientBuffer.data(), bytesRead);
					if (bytesSent < 0)
					{
						destClosed = true;
					}
				}
				else if (bytesRead == 0 || (bytesRead < 0 && wsocket_get_last_error().value() != WSAEWOULDBLOCK))
				{
					clientClosed = true;
				}
			}
			// Check for data from destination
			if (!destClosed)
			{
				int bytesRead = destSocket->tcp_recv_data(destBuffer.data(), (int)destBuffer.size());
				if (bytesRead > 0)
				{
					// Forward data to client
					int bytesSent = client->tcp_send_data(destBuffer.data(), bytesRead);
					if (bytesSent < 0)
					{
						clientClosed = true;
					}
				}
				else if (bytesRead == 0 || (bytesRead < 0 && wsocket_get_last_error().value() != WSAEWOULDBLOCK))
				{
					destClosed = true;
				}
			}
			// Small delay to prevent CPU hogging
			std::this_thread::sleep_for(std::chrono::milliseconds(1));
		}
		// Close destination socket
		destSocket->disconnect();

		return true;
	}
	bool Socks5Server::handle_udp_associate(PWSocket client, const std::string& dest_addr, uint16_t dest_port)
	{			
		/*
		Procedure for UDP-based clients
			+----+------+------+----------+----------+----------+
			|RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
			+----+------+------+----------+----------+----------+
			| 2  |  1   |  1   | Variable |    2     | Variable |
			+----+------+------+----------+----------+----------+
		*/

		//TODO: Handling...


		return false;
	}
}