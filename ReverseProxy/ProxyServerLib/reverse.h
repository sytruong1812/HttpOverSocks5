#pragma once
#include "socket.h"

namespace NetworkOperations
{
	class ReverseServer
	{
	public:
		ReverseServer(const Endpoint& serverEndpoint, const Endpoint& backendEndpoint);
		ReverseServer(const std::string& serverAddress, uint16_t serverPort, const std::string& backendAddress, uint16_t backendPort);
		~ReverseServer();
		bool Start();
		void Run();
		void Stop();
	private:
		void process_handle_client(SOCKET fd, const Endpoint& endpoint);
		bool redirection(PWSocket client);
		bool caching_data(PWSocket client);
		bool load_balancing(PWSocket client);
		bool forward_traffic(PWSocket client, const std::string& request);
		bool request_modification(PWSocket client);
		bool response_modification(PWSocket client);
	private:
		bool _running;
		Endpoint _serverEndpoint;
		Endpoint _backendEndpoint;
		std::shared_ptr<WSocket> _serverSocket;
		std::shared_ptr<WSocket> _backendSocket;
	};
}