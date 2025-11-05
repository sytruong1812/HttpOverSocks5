#include "endpoint.h"

namespace NetworkOperations
{
	Endpoint sockaddr_to_endpoint(const SOCKADDR_STORAGE_LH& addr)
	{
		Endpoint endpoint;
		if (addr.ss_family == AF_INET6)
		{
			const sockaddr_in6* addr6 = reinterpret_cast<const sockaddr_in6*>(&addr);
			endpoint.address.family = AddressFamily::IPv6;
			memcpy(endpoint.address.addr.ipv6, &addr6->sin6_addr, sizeof(endpoint.address.addr.ipv6));
			endpoint.port = ntohs(addr6->sin6_port);
		}
		else
		{
			const sockaddr_in* addr4 = reinterpret_cast<const sockaddr_in*>(&addr);
			endpoint.address.family = AddressFamily::IPv4;
			memcpy(endpoint.address.addr.ipv4, &addr4->sin_addr, sizeof(endpoint.address.addr.ipv4));
			endpoint.port = ntohs(addr4->sin_port);
		}
		return endpoint;
	}

	int endpoint_to_sockaddr(const Endpoint& endpoint, SOCKADDR_STORAGE_LH& addr)
	{
		int addr_len = 0;
		if (endpoint.address.family == AddressFamily::IPv6)
		{
			sockaddr_in6* addr6 = reinterpret_cast<sockaddr_in6*>(&addr);
			addr6->sin6_family = AF_INET6;
			addr6->sin6_port = htons(endpoint.port);
			memcpy(&addr6->sin6_addr, endpoint.address.addr.ipv6, sizeof(endpoint.address.addr.ipv6));
			addr_len = sizeof(sockaddr_in6);
		}
		else
		{
			sockaddr_in* addr4 = reinterpret_cast<sockaddr_in*>(&addr);
			addr4->sin_family = AF_INET;
			addr4->sin_port = htons(endpoint.port);
			memcpy(&addr4->sin_addr, endpoint.address.addr.ipv4, sizeof(endpoint.address.addr.ipv4));
			addr_len = sizeof(sockaddr_in);
		}
		return addr_len;
	}

	bool is_valid_ipv4_address(const char* ip)
	{
		struct sockaddr_in sa = {};
		int result = inet_pton(AF_INET, ip, &(sa.sin_addr));
		return result != 0;
	}

	bool is_valid_ipv6_address(const char* ip)
	{
		struct sockaddr_in6 sa = {};
		int result = inet_pton(AF_INET6, ip, &(sa.sin6_addr));
		return result != 0;
	}

	std::vector<IpAddress> dns_resolve_hostname(const char* hostname, AddressFamily family)
	{
		std::vector<IpAddress> results;
		addrinfo hints = {};
		hints.ai_family = (family == AddressFamily::IPv6) ? AF_INET6 
			: (family == AddressFamily::IPv4) ? AF_INET 
			: AF_UNSPEC;
		addrinfo* addr_result = nullptr;
		int error = getaddrinfo(hostname, nullptr, &hints, &addr_result);
		if (error != 0)
		{
			return results;
		}
		// Smart pointer for automatic cleanup
		std::unique_ptr<addrinfo, decltype(&freeaddrinfo)> addr_list(addr_result, freeaddrinfo);

		for (addrinfo* addr = addr_list.get(); addr != nullptr; addr = addr->ai_next)
		{
			IpAddress ip;
			if (addr->ai_family == AF_INET)
			{
				sockaddr_in* addr4 = reinterpret_cast<sockaddr_in*>(addr->ai_addr);
				ip.family = AddressFamily::IPv4;
				memcpy(ip.addr.ipv4, &addr4->sin_addr, sizeof(ip.addr.ipv4));
				results.push_back(ip);
			}
			else if (addr->ai_family == AF_INET6)
			{
				sockaddr_in6* addr6 = reinterpret_cast<sockaddr_in6*>(addr->ai_addr);
				ip.family = AddressFamily::IPv6;
				memcpy(ip.addr.ipv6, &addr6->sin6_addr, sizeof(ip.addr.ipv6));
				results.push_back(ip);
			}
		}
		return results;
	}
}