#include "socket.h"

namespace NetworkOperations
{
	void wsocket_global_startup()
	{
		WSADATA wsa;
		if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
		{
			auto error = wsocket_get_last_error();
			LOG_ERROR_A("[-] WSAStartup error[%d]: %s", error.value(), error.message().c_str());
		}
	}

	void wsocket_global_cleanup()
	{
		if (WSACleanup() == SOCKET_ERROR)
		{
			auto error = wsocket_get_last_error();
			LOG_ERROR_A("[-] WSASCleanup error[%d]: %s", error.value(), error.message().c_str());
		}
	}

	std::error_code wsocket_get_last_error()
	{
		return std::error_code(WSAGetLastError(), std::system_category());
	}

	WSocket::WSocket(AddressFamily family, WSocketTypes type)
	{
		this->_is_connected = false;
		this->_is_shutdown = false;

		int sock_af =  (family == AddressFamily::IPv6) ? AF_INET6 : AF_INET;
		int sock_type = (type == WSocketTypes::UDP_DATAGRAM) ? SOCK_DGRAM : SOCK_STREAM;
		int protocol = (type == WSocketTypes::UDP_DATAGRAM) ? IPPROTO_UDP : IPPROTO_TCP;

		this->_fd = ::socket(sock_af, sock_type, protocol);
		if (this->_fd == INVALID_SOCKET)
		{
			auto error = wsocket_get_last_error();
			LOG_ERROR_A("[-][WSocket] Creating socket error[%d]: %s", error.value(), error.message().c_str());
		}
		else
		{
			if (family == AddressFamily::IPv6)
			{
				int disable = 0;
				LOG_INFO_A("[+][WSocket] Enable dual-stack (optional): %d", disable);
				::setsockopt(this->_fd, IPPROTO_IPV6, IPV6_V6ONLY, (char*)&disable, sizeof(disable));
			}
		}
	}

	WSocket::WSocket(SOCKET fd)
	{
		this->_fd = fd;
		this->_is_shutdown = false;
		this->_is_connected = false;
	}

	WSocket::~WSocket()
	{
		disconnect();
	}

	bool WSocket::is_connected() const
	{
		return _is_connected;
	}

	SOCKET WSocket::get_socket() const
	{
		return _fd;
	}

	bool WSocket::bind(const Endpoint& endpoint)
	{
		SOCKADDR_STORAGE_LH addr;
		int addr_len = endpoint_to_sockaddr(endpoint, addr);

		// Bind the socket to local server address
		int result = ::bind(this->_fd, (LPSOCKADDR)&addr, addr_len);
		if (result == SOCKET_ERROR)
		{
			auto error = wsocket_get_last_error();
			LOG_ERROR_A("[-][WSocket] Binding socket error[%d]: %s", error.value(), error.message().c_str());
		}
		return result == NO_ERROR;
	}

	bool WSocket::listen(const int backlog)
	{
		// Allow socket to listen
		int result = ::listen(this->_fd, backlog);
		if (result == SOCKET_ERROR)
		{
			auto error = wsocket_get_last_error();
			LOG_ERROR_A("[-][WSocket] Listen error[%d]: %s", error.value(), error.message().c_str());
		}
		return result == NO_ERROR;
	}

	SOCKET WSocket::accept(Endpoint& endpoint)
	{
		SOCKADDR_STORAGE_LH client_addr;
		int client_addr_len = sizeof(client_addr);

		SOCKET client_fd = ::accept(this->_fd, (LPSOCKADDR)&client_addr, &client_addr_len);
		if (client_fd != INVALID_SOCKET)
		{
			endpoint = sockaddr_to_endpoint(client_addr);
		}
		return client_fd;
	}

	bool WSocket::connect(const Endpoint& endpoint)
	{
		SOCKADDR_STORAGE_LH addr;
		int addr_len = endpoint_to_sockaddr(endpoint, addr);

		int result = ::connect(this->_fd, (LPSOCKADDR)&addr, addr_len);
		if (result == SOCKET_ERROR)
		{
			auto error = wsocket_get_last_error();
			LOG_ERROR_A("[-][WSocket] Connect error[%d]: %s", error.value(), error.message().c_str());
		}
		else 
		{
			_is_connected = true;
		}
		return result == NO_ERROR;
	}

	bool WSocket::set_nonblocking(bool enable)
	{
		//-------------------------
		// Set the socket I/O mode: In this case FIONBIO enables or disables 
		// the blocking mode for the socket based on the numerical value of mode.
		// If mode = 0, blocking is enabled; 
		// If mode != 0, non-blocking mode is enabled.
		u_long mode = enable ? 1UL : 0UL;
		if (::ioctlsocket(_fd, FIONBIO, &mode) != NO_ERROR) 
		{
			auto error = wsocket_get_last_error();
			LOG_ERROR_A("[-][WSocket] Set socket I/O mode error [%d]: %s", error.value(), error.message().c_str());
			return false;
		}
		return true;
	}

	bool WSocket::set_socket_opt(int optname, const char* optval, int optlen)
	{
		if (::setsockopt(this->_fd, SOL_SOCKET, optname, optval, optlen) < 0)
		{
			return false;
		}
		return true;
	}

	bool WSocket::set_recv_timeout(unsigned int time_msec)
	{
		if (::setsockopt(this->_fd, SOL_SOCKET, SO_RCVTIMEO, (char*)&time_msec, sizeof(struct timeval)) < 0)
		{
			return false;
		}
		return true;
	}

	bool WSocket::set_send_timeout(unsigned int time_msec)
	{
		if (::setsockopt(this->_fd, SOL_SOCKET, SO_SNDTIMEO, (char*)&time_msec, sizeof(struct timeval)) < 0)
		{
			return false;
		}
		return true;
	}

	int WSocket::tcp_send_data(const char* data, int len)
	{
		int bytes_sented = ::send(this->_fd, data, len, 0);
		if (bytes_sented == SOCKET_ERROR)
		{
			std::error_code error = wsocket_get_last_error();
			if (error.value() == WSAETIMEDOUT)
			{
				LOG_ERROR_A("[-][WSocket] Send timeout.");
				return ERROR_TCP_TIMEOUT;
			}
			else if (error.value() == WSAEWOULDBLOCK) 
			{
				return ERROR_TCP_WOULD_BLOCK;
			}
			LOG_ERROR_A("[-][WSocket] Send error[%d]: %s", error.value(), error.message().c_str());
			return ERROR_TCP_SEND;
		}
		return bytes_sented;
	}

	int WSocket::tcp_recv_data(char* data, int len)
	{
		int bytes_received = ::recv(this->_fd, data, len, 0);
		if (bytes_received == SOCKET_ERROR)
		{
			std::error_code error = wsocket_get_last_error();
			if (error.value() == WSAETIMEDOUT)
			{
				LOG_ERROR_A("[-][WSocket] Recv timeout.");
				return ERROR_TCP_TIMEOUT;
			}
			else if (error.value() == WSAEWOULDBLOCK) 
			{
				return ERROR_TCP_WOULD_BLOCK;
			}
			LOG_ERROR_A("[-][WSocket] Recv error[%d]: %s", error.value(), error.message().c_str());
			return ERROR_TCP_RECV;
		}
		return bytes_received;
	}

	int WSocket::tcp_send_timeout(const char* data, int len, unsigned int time_msec)
	{
		if (::setsockopt(this->_fd, SOL_SOCKET, SO_SNDTIMEO, (char*)&time_msec, sizeof(struct timeval)) < 0)
		{
			LOG_ERROR_A("[-][WSocket] Failed to set send timeout!");
			return ERROR_INTERNAL;
		}
		return tcp_send_data(data, len);
	}

	int WSocket::tcp_recv_timeout(char* data, int len, unsigned int time_msec)
	{
		if (::setsockopt(this->_fd, SOL_SOCKET, SO_RCVTIMEO, (char*)&time_msec, sizeof(struct timeval)) < 0)
		{
			LOG_ERROR_A("[-][WSocket] Failed to set recv timeout!");
			return ERROR_INTERNAL;
		}
		return tcp_recv_data(data, len);
	}

	int WSocket::tcp_send_data_select_based(const char* data, int len)
	{
		fd_set writefds;
		FD_ZERO(&writefds);
		FD_SET(this->_fd, &writefds);
		struct timeval timeout = { 0 };

		int bytes_sented = 0;
		while (::select((int)(this->_fd + 1), &writefds, NULL, NULL, &timeout) == 1)
		{
			bytes_sented = ::send(this->_fd, data, len, 0);
			if (bytes_sented == SOCKET_ERROR)
			{
				std::error_code error = wsocket_get_last_error();
				if (error.value() == WSAETIMEDOUT)
				{
					LOG_ERROR_A("[-][WSocket] Send timeout.");
					return ERROR_TCP_TIMEOUT;
				}
				LOG_ERROR_A("[-][WSocket] Send error[%d]: %s", error.value(), error.message().c_str());
				return ERROR_TCP_SEND;
			}
			else
			{
				if (bytes_sented == len)
				{
					break;
				}
			}
		}
		return bytes_sented;
	}

	int WSocket::tcp_recv_data_select_based(char* data, int len)
	{
		fd_set readfds;
		FD_ZERO(&readfds);
		FD_SET(this->_fd, &readfds);
		struct timeval timeout = { 0 };

		int bytes_received = 0;
		while (::select((int)(this->_fd + 1), &readfds, NULL, NULL, &timeout) == 1)
		{
			bytes_received = ::recv(this->_fd, data, len, 0);
			if (bytes_received == SOCKET_ERROR)
			{
				std::error_code error = wsocket_get_last_error();
				if (error.value() == WSAETIMEDOUT)
				{
					LOG_ERROR_A("[-][WSocket] Recv timeout.");
					return ERROR_TCP_TIMEOUT;
				}
				LOG_ERROR_A("[-][WSocket] Recv error[%d]: %s", error.value(), error.message().c_str());
				return ERROR_TCP_RECV;
			}
			else
			{
				if (bytes_received == len)
				{
					break;
				}
			}
		}
		return bytes_received;
	}

	int WSocket::udp_send_to(const Endpoint& endpoint, const char* data, int len)
	{
		sockaddr_storage addr;
		int addr_len = endpoint_to_sockaddr(endpoint, addr);
		int	sended = ::sendto(this->_fd, data, len, 0, (LPSOCKADDR)&addr, addr_len);
		if (sended == SOCKET_ERROR)
		{
			LOG_ERROR_A("[-][WSocket] UDP sendto failed: %d", WSAGetLastError());
			return ERROR_UDP_SEND_TO;
		}
		return sended;
	}

	int WSocket::udp_recv_from(Endpoint& endpoint, char* data, int len)
	{
		sockaddr_storage addr;
		int addr_len = sizeof(addr);
		int total_bytes_received = 0;

		total_bytes_received = ::recvfrom(this->_fd, data, len, 0, (SOCKADDR*)&addr, &addr_len);
		if (total_bytes_received == SOCKET_ERROR)
		{
			int error = WSAGetLastError();
			if (error == WSAEMSGSIZE)
			{
				LOG_ERROR_A("[-][WSocket] UDP packet truncated (buffer too small)");
				return ERROR_BUFFER_TOO_SMALL;
			}
			LOG_ERROR_A("[-][WSocket] UDP recvfrom failed: %d", error);
			return ERROR_UDP_RECV_FROM;
		}
		endpoint = sockaddr_to_endpoint(addr);
		return total_bytes_received;
	}

	void WSocket::shutdown(int how)
	{
		if (this->_fd)
		{
			::shutdown(this->_fd, how);
			_is_shutdown = true;
		}
	}

	void WSocket::disconnect()
	{
		if (this->_fd)
		{
			::closesocket(this->_fd);
			_is_connected = false;
		}
	}
	
}	// NetworkOperations