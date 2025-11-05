#pragma once
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <thread>
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <system_error>
#if defined(_MSC_VER)
#if defined(_WIN32_WCE)
#pragma comment(lib, "ws2.lib" )
#else
#pragma comment(lib, "ws2_32.lib" )
#endif
#endif /* _MSC_VER */

#include "error.h"
#include "endpoint.h"
#include "TraceLogger.h"

#define BUFFER_SIZE (1024 * 4)

namespace NetworkOperations
{
	// Global function
	void wsocket_global_startup();
	void wsocket_global_cleanup();
	// Helper function
	std::error_code wsocket_get_last_error();

	enum class WSocketTypes
	{
		TCP_STREAM,
		UDP_DATAGRAM,
	};
	class WSocket
	{
	public:
		WSocket(AddressFamily family = AddressFamily::IPv4, WSocketTypes type = WSocketTypes::TCP_STREAM);
		WSocket(SOCKET fd);
		~WSocket();
		bool is_connected() const;
		SOCKET get_socket() const;
		bool bind(const Endpoint& endpoint);
		bool listen(const int backlog = SOMAXCONN);
		SOCKET accept(Endpoint& endpoint);
		bool connect(const Endpoint& endpoint);
		bool set_nonblocking(bool enable);
		bool set_socket_opt(int optname, const char* optval, int optlen);
		bool set_recv_timeout(unsigned int time_msec);
		bool set_send_timeout(unsigned int time_msec);
		int tcp_recv_data(char* data, int len);
		int tcp_send_data(const char* data, int len);
		int tcp_recv_timeout(char* data, int len, unsigned int time_msec);
		int tcp_send_timeout(const char* data, int len, unsigned int time_msec);
		int tcp_recv_data_select_based(char* data, int len);
		int tcp_send_data_select_based(const char* data, int len);
		int udp_recv_from(Endpoint& endpoint, char* data, int len);
		int udp_send_to(const Endpoint& endpoint, const char* data, int len);
		void shutdown(int how = SD_BOTH);
		void disconnect();
	private:
		bool _is_connected;
		bool _is_shutdown;
		SOCKET _fd;
	}; 
	typedef WSocket* PWSocket;
}