#include <vector>
#include "socket.h"

namespace NetworkOperations 
{

	WSocket::WSocket(SOCKET_TYPES type, bool enable_ipv6)
	{
		this->_is_connected = false;
		this->_is_shutdown = false;

		int sock_af = (this->_is_ipv6 = enable_ipv6) ? AF_INET6 : AF_INET;
		int sock_type = (type == SOCKET_TYPES::UDP_DATAGRAM) ? SOCK_DGRAM : SOCK_STREAM;
		int protocol = (type == SOCKET_TYPES::UDP_DATAGRAM) ? IPPROTO_UDP : IPPROTO_TCP;

		this->_fd = ::socket(sock_af, sock_type, protocol);
		if (this->_fd == INVALID_SOCKET)
		{
			LOG_ERROR_A("[-][WSocket] Error creating socket: %d", WSAGetLastError());
		}
		else {
			if (_is_ipv6)
			{
				int disable = 0;
				LOG_INFO_A("[+][WSocket] Enable dual-stack (optional): %d", disable);
				setsockopt(this->_fd, IPPROTO_IPV6, IPV6_V6ONLY, (char*)&disable, sizeof(disable));
			}
		}
	}

	WSocket::~WSocket()
	{
		disconnect();
	}

	void* WSocket::get_socket() const
	{
		return (void*)_fd;
	}

	int WSocket::connect(const char* host, int port)
	{
		int result = SOCKET_ERROR;
		if (!host || port == 0)
		{
			return ERROR_INVALID_PARAM;
		}
		char* ip_resolve = nullptr;
		if (!dns_local_resolve(host, _is_ipv6, &ip_resolve))
		{
			return ERROR_INTERNAL;
		}
		if (!ip_resolve)
		{
			return ERROR_INTERNAL;
		}
		if (_is_ipv6)
		{
			sockaddr_in6 addr6 = {};
			addr6.sin6_family = AF_INET6;
			addr6.sin6_port = htons(port);
			if (inet_pton(AF_INET6, ip_resolve, &addr6.sin6_addr) != 1)
			{
				LOG_ERROR_A("[-][WSocket] Invalid IPv6 address: %s", ip_resolve);
				return ERROR_INTERNAL;
			}
			result = ::connect(_fd, (sockaddr*)&addr6, sizeof(addr6));
		}
		else
		{
			sockaddr_in addr4 = {};
			addr4.sin_family = AF_INET;
			addr4.sin_port = htons(port);
			if (inet_pton(AF_INET, ip_resolve, &addr4.sin_addr) != 1)
			{
				LOG_ERROR_A("[-][WSocket] Invalid IPv4 address: %s", ip_resolve);
				return ERROR_INTERNAL;
			}
			result = ::connect(_fd, (sockaddr*)&addr4, sizeof(addr4));
		}
		if (result == SOCKET_ERROR)
		{
			auto error = wsocket_get_last_error();
			LOG_ERROR_A("[-][WSocket] Connect error[%d]: %s", error.value(), error.message().c_str());
		}
		else
		{
			_is_connected = true;
		}
		if (ip_resolve)
		{
			delete[] ip_resolve;
		}
		return result == 0 ? SOCKET_OK : ERROR_CONNECTION;
	}

	bool WSocket::set_nonblocking(unsigned long enable)
	{
		return ioctlsocket(_fd, FIONBIO, &enable) < 0 ? false : true;
	}

	bool WSocket::set_socket_opt(int optname, const char* optval, int optlen)
	{
		if (::setsockopt(_fd, SOL_SOCKET, optname, optval, optlen) < 0)
		{
			return false;
		}
		return true;
	}

	bool WSocket::set_read_timeout(unsigned int time_msec)
	{
		if (::setsockopt(_fd, SOL_SOCKET, SO_RCVTIMEO, (char*)&time_msec, sizeof(struct timeval)) < 0)
		{
			return false;
		}
		return true;
	}

	bool WSocket::set_write_timeout(unsigned int time_msec)
	{
		if (::setsockopt(_fd, SOL_SOCKET, SO_SNDTIMEO, (char*)&time_msec, sizeof(struct timeval)) < 0)
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
		if (::setsockopt(_fd, SOL_SOCKET, SO_SNDTIMEO, (char*)&time_msec, sizeof(struct timeval)) < 0)
		{
			LOG_ERROR_A("[-][WSocket] Failed to set send timeout!");
			return ERROR_INTERNAL;
		}
		return tcp_send_data(data, len);
	}

	int WSocket::tcp_recv_timeout(char* data, int len, unsigned int time_msec)
	{
		if (::setsockopt(_fd, SOL_SOCKET, SO_RCVTIMEO, (char*)&time_msec, sizeof(struct timeval)) < 0)
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
		FD_SET(_fd, &writefds);
		struct timeval timeout = { 0 };

		int bytes_sented = 0;
		while (::select((int)(_fd + 1), &writefds, NULL, NULL, &timeout) == 1)
		{
			bytes_sented = ::send(_fd, data, len, 0);
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
		FD_SET(_fd, &readfds);
		struct timeval timeout = { 0 };

		int bytes_received = 0;
		while (::select((int)(_fd + 1), &readfds, NULL, NULL, &timeout) == 1)
		{
			bytes_received = ::recv(_fd, data, len, 0);
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

	int WSocket::udp_send_to(const char* dest_addr, int dest_port, const char* data, int len)
	{
		int sended = SOCKET_ERROR;
		if (_is_ipv6)
		{

			sockaddr_in6 to6 = {};
			to6.sin6_family = AF_INET6;
			to6.sin6_port = htons(dest_port);
			if (inet_pton(AF_INET6, dest_addr, &to6.sin6_addr) != 1)
			{
				LOG_ERROR_A("[-][WSocket] Invalid IPv6 address: %s", dest_addr);
				return ERROR_INTERNAL;
			}
			sended = ::sendto(_fd, data, len, 0, (SOCKADDR*)&to6, sizeof(to6));
		}
		else
		{
			sockaddr_in to4 = {};
			to4.sin_family = AF_INET;
			to4.sin_port = htons(dest_port);
			if (inet_pton(AF_INET, dest_addr, &to4.sin_addr) != 1)
			{
				LOG_ERROR_A("[-][WSocket] Invalid IPv4 address: %s", dest_addr);
				return ERROR_INTERNAL;
			}
			sended = ::sendto(_fd, data, len, 0, (SOCKADDR*)&to4, sizeof(to4));
		}
		if (sended == SOCKET_ERROR)
		{
			LOG_ERROR_A("[-][WSocket] UDP sendto failed: %d", WSAGetLastError());
			return ERROR_UDP_SEND_TO;
		}
		return sended;
	}

	int WSocket::udp_recv_from(char** sender_addr, int* sender_port, char* data, int len)
	{
		int bytes_received = 0;
		if (!sender_addr || !sender_port)
		{
			return ERROR_INVALID_PARAM;
		}
		if (_is_ipv6)
		{
			sockaddr_in6 from6 = {};
			int from_len = sizeof(from6);
			bytes_received = ::recvfrom(_fd, data, len, 0, (SOCKADDR*)&from6, &from_len);
			if (bytes_received == SOCKET_ERROR)
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
			*sender_addr = new char[INET6_ADDRSTRLEN];
			if (!*sender_addr)
			{
				return ERROR_ALLOCATING_MEMORY;
			}
			inet_ntop(AF_INET6, &from6.sin6_addr, *sender_addr, INET6_ADDRSTRLEN);
			*sender_port = ntohs(from6.sin6_port);
		}
		else
		{
			sockaddr_in from4 = {};
			int from_len = sizeof(from4);
			bytes_received = ::recvfrom(_fd, data, len, 0, (SOCKADDR*)&from4, &from_len);
			if (bytes_received == SOCKET_ERROR)
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
			*sender_addr = new char[INET_ADDRSTRLEN];
			if (!*sender_addr)
			{
				return ERROR_ALLOCATING_MEMORY;
			}
			inet_ntop(AF_INET, &from4.sin_addr, *sender_addr, INET_ADDRSTRLEN);
			*sender_port = ntohs(from4.sin_port);		
		}
		return bytes_received;
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
		if (_fd)
		{
			::closesocket(_fd);
			_is_connected = false;
		}
	}

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

	bool dns_local_resolve(const char* hostname, bool is_ipv6, char** ip_resolve)
	{
		if (!hostname || !ip_resolve)
		{
			return false;
		}
		addrinfo hints = {};
		memset(&hints, 0, sizeof(hints));
		hints.ai_family = is_ipv6 ? AF_INET6 : AF_INET;
		hints.ai_socktype = SOCK_STREAM;

		addrinfo* results = nullptr;
		int status = ::getaddrinfo(hostname, nullptr, &hints, &results);
		if (status != 0 || !results)
		{
			return false;
		}
		bool resolved = false;
		*ip_resolve = new char[INET6_ADDRSTRLEN];
		if (!*ip_resolve)
		{
			::freeaddrinfo(results);
			return false;
		}
		for (addrinfo* temp = results; temp != nullptr; temp = temp->ai_next)
		{
			void* addr_ptr = nullptr;
			if (is_ipv6)
			{
				sockaddr_in6* ipv6 = reinterpret_cast<sockaddr_in6*>(temp->ai_addr);
				addr_ptr = &(ipv6->sin6_addr);
			}
			else
			{
				sockaddr_in* ipv4 = reinterpret_cast<sockaddr_in*>(temp->ai_addr);
				addr_ptr = &(ipv4->sin_addr);
			}
			if (addr_ptr)
			{
				int ip_resolve_len = is_ipv6 ? INET6_ADDRSTRLEN : INET_ADDRSTRLEN;
				if (::inet_ntop(temp->ai_family, addr_ptr, *ip_resolve, ip_resolve_len))
				{
					resolved = true;
					break;
				}
			}
		}
		::freeaddrinfo(results);
		return resolved ? true : false;
	}

}	// NetworkOperations