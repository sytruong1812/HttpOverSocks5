#pragma once
#include <string>
#include <vector>
#include <memory>
#include <cstdint>
#include <ws2tcpip.h>

namespace NetworkOperations
{
	enum class AddressFamily
	{
		IPv4,
		IPv6,
		UNSPECIFIED
	};

	// IP address representation
	struct IpAddress
	{
		AddressFamily family = AddressFamily::IPv4;
		union
		{
			uint8_t ipv4[4];
			uint8_t ipv6[16];
		} addr;
		// Create an IPv4 address with all zeros (0.0.0.0)
		static IpAddress IPv4Any()
		{
			IpAddress addr;
			addr.family = AddressFamily::IPv4;
			addr.addr.ipv4[0] = 0;
			addr.addr.ipv4[1] = 0;
			addr.addr.ipv4[2] = 0;
			addr.addr.ipv4[3] = 0;
			return addr;
		}
		bool is_ipv4() const { return family == AddressFamily::IPv4; }
		bool is_ipv6() const { return family == AddressFamily::IPv6; }
		const uint8_t* get_ipv4_bytes() const { return addr.ipv4; }
		const uint8_t* get_ipv6_bytes() const { return addr.ipv6; }
		std::string to_string() const
		{
			char buffer[INET6_ADDRSTRLEN];
			if (family == AddressFamily::IPv6)
			{
				inet_ntop(AF_INET6, addr.ipv6, buffer, sizeof(buffer));
			}
			else
			{
				inet_ntop(AF_INET, addr.ipv4, buffer, sizeof(buffer));
			}
			return std::string(buffer);
		}
		static IpAddress from_string(const char* ip)
		{
			IpAddress result;
			// Try IPv4 first
			in_addr addr4;
			if (inet_pton(AF_INET, ip, &addr4) == 1)
			{
				result.family = AddressFamily::IPv4;
				::memcpy(result.addr.ipv4, &addr4, sizeof(addr4));
			}
			// Try IPv6
			in6_addr addr6;
			if (inet_pton(AF_INET6, ip, &addr6) == 1)
			{
				result.family = AddressFamily::IPv6;
				::memcpy(result.addr.ipv6, &addr6, sizeof(addr6));
			}
			return result;
		}
	};

	// Endpoint (IP + port)
	struct Endpoint
	{
		uint16_t port = 0;
		IpAddress address;
		std::string to_string() const
		{
			return address.to_string() + ":" + std::to_string(port);
		}
		static Endpoint from_string(const char* ip, uint16_t port)
		{
			Endpoint endpoint;
			endpoint.address = IpAddress::from_string(ip);
			endpoint.port = port;
			return endpoint;
		}
	};

	/// <summary>
	/// Helper to convert sockaddr to Endpoint
	/// </summary>
	/// <param name="addr"></param>
	/// <returns></returns>
	Endpoint sockaddr_to_endpoint(const SOCKADDR_STORAGE_LH& addr);

	/// <summary>
	/// Helper to convert Endpoint to sockaddr
	/// </summary>
	/// <param name="endpoint"></param>
	/// <param name="addr"></param>
	/// <returns></returns>
	int endpoint_to_sockaddr(const Endpoint& endpoint, SOCKADDR_STORAGE_LH& addr);

	/// <summary>
	/// Determine if a string is a valid ipv4 address
	/// </summary>
	/// <param name="ip"></param>
	/// <returns></returns>
	bool is_valid_ipv4_address(const char* ip);

	/// <summary>
	/// Determine if a string is a valid ipv6 address
	/// </summary>
	/// <param name="ip"></param>
	/// <returns></returns>
	bool is_valid_ipv6_address(const char* ip);

	/// <summary>
	/// Helper resolve hostname to IP address: "example.com" -> "127.0.0.1" and "93.184.216.34"
	/// </summary>
	/// <param name="hostname"></param>
	/// <param name="family"></param>
	/// <returns></returns>
	std::vector<IpAddress> dns_resolve_hostname(const char* hostname, AddressFamily family = AddressFamily::UNSPECIFIED);

}