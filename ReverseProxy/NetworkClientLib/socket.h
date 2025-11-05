#pragma once
#include <memory>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <system_error>
#if defined(_MSC_VER)
#if defined(_WIN32_WCE)
#pragma comment(lib, "ws2.lib" )
#else
#pragma comment(lib, "ws2_32.lib" )
#endif
#endif /* _MSC_VER */

#include "TraceLogger.h"

#define BUFFER_SIZE (1024 * 4)

#define SOCKET_OK 1
#define ERROR_INTERNAL -1
#define ERROR_INVALID_PARAM -2
#define ERROR_BUFFER_TOO_SMALL -3
#define ERROR_ALLOCATING_MEMORY -4
#define ERROR_CONNECTION -5
#define ERROR_TCP_RECV -6
#define ERROR_TCP_SEND -7
#define ERROR_TCP_TIMEOUT -8
#define ERROR_UDP_RECV_FROM -9
#define ERROR_UDP_SEND_TO -10
#define ERROR_TCP_WOULD_BLOCK -11

namespace NetworkOperations 
{
	class ITransport 
	{
	public:
		virtual ~ITransport() = default;
		virtual void* get_socket() const = 0;
		virtual int connect(const char* host, int port) = 0;
		virtual int tcp_send_data(const char* data, int len) = 0;
		virtual int tcp_recv_data(char* data, int len) = 0;
		virtual int tcp_send_timeout(const char* data, int len, unsigned int time_msec) = 0;
		virtual int tcp_recv_timeout(char* data, int len, unsigned int time_msec) = 0;
		virtual int tcp_send_data_select_based(const char* data, int len) = 0;
		virtual int tcp_recv_data_select_based(char* data, int len) = 0;
		virtual int udp_send_to(const char* dest_addr, int dest_port, const char* data, int len) = 0;
		virtual int udp_recv_from(char** sender_addr, int* sender_port, char* data, int len) = 0;
		virtual void shutdown(int how) = 0;
		virtual void disconnect() = 0;
	};

	enum class SOCKET_TYPES
	{
		TCP_STREAM,
		UDP_DATAGRAM,
	};

	class WSocket : public ITransport 
	{
	public:
		WSocket(SOCKET_TYPES type = SOCKET_TYPES::TCP_STREAM, bool enable_ipv6 = false);
		~WSocket() override;
		void* get_socket() const override;
		int connect(const char* host, int port) override;
		bool set_nonblocking(unsigned long enable = 1);
		bool set_socket_opt(int optname, const char* optval, int optlen);
		bool set_read_timeout(unsigned int time_msec);
		bool set_write_timeout(unsigned int time_msec);
		int tcp_send_data(const char* data, int len) override;
		int tcp_recv_data(char* data, int len) override;
		int tcp_send_timeout(const char* data, int len, unsigned int time_msec) override;
		int tcp_recv_timeout(char* data, int len, unsigned int time_msec) override;
		int tcp_send_data_select_based(const char* data, int len) override;
		int tcp_recv_data_select_based(char* data, int len) override;
		int udp_send_to(const char* dest_addr, int dest_port, const char* data, int len) override;
		int udp_recv_from(char** sender_addr, int* sender_port, char* data, int len) override;
		void shutdown(int how = SD_BOTH) override;
		void disconnect() override;
	private:
		bool _is_connected;
		bool _is_shutdown;
		bool _is_ipv6;
		SOCKET _fd;
	};

	// Global function
	void wsocket_global_startup();
	void wsocket_global_cleanup();
	// Helper function
	std::error_code wsocket_get_last_error();
	// Helper function: Resolve hostname to ip: "example.com" -> "93.184.216.34"
	bool dns_local_resolve(const char* hostname, bool is_ipv6, char** ip_resolve);

} 	// NetworkOperations