#pragma once
#include <thread>
#include <signal.h>
#include <iostream>
#include "socks5.h"
#include "reverse.h"
#include "TraceLogger.h"

#define PROXY_SERVER_IP         "0.0.0.0"
#define PROXY_SERVER_PORT       8001
#define SOCKS5_SERVER_PORT      4444
#define BACKEND_DOMAIN          "cloudfilestorage"
#define BACKEND_IP              "127.0.0.2"
#define BACKEND_PORT            8080

using namespace NetworkOperations;

// Global flag for signal handling
std::atomic<bool> g_running(true);

// Handler for SIGINT, triggered by Ctrl-C at the keyboard 
void signalHandler(int signal)
{
	g_running = false;
}

void TEST_SOCKS5_SERVER()
{
	// Register signal handlers
	signal(SIGINT, signalHandler);
	signal(SIGTERM, signalHandler);
	std::cout << "[!] Press Ctrl-C to stop the server." << std::endl;

	Socks5Server server(PROXY_SERVER_IP, SOCKS5_SERVER_PORT);
	if (server.Start())
	{
		// Run server in main thread
		std::thread main_thread([&server]()
		{
			server.Run();
		});

		// Wait for signal to stop
		while (g_running)
		{
			std::this_thread::sleep_for(std::chrono::milliseconds(100));
		}
		// Stop servers
		std::cout << "[+] Stopping servers...";
		server.Stop();

		// Wait for threads to finish
		if (main_thread.joinable())
		{
			main_thread.join();
		}
		std::cout << " done!" << std::endl;
	}
}

void TEST_REVERSE_PROXY_SERVER()
{
	// Register signal handlers
	signal(SIGINT, signalHandler);
	signal(SIGTERM, signalHandler);
	std::cout << "[!] Press Ctrl-C to stop the server." << std::endl;

	ReverseServer server(PROXY_SERVER_IP, PROXY_SERVER_PORT, BACKEND_IP, BACKEND_PORT);
	if (server.Start())
	{
		// Run server in main thread
		std::thread main_thread([&server]()
		{
			server.Run();
		});

		// Wait for signal to stop
		while (g_running)
		{
			std::this_thread::sleep_for(std::chrono::milliseconds(100));
		}
		// Stop servers
		std::cout << "[+] Stopping servers...";
		server.Stop();

		// Wait for threads to finish
		if (main_thread.joinable())
		{
			main_thread.join();
		}
		std::cout << " done!" << std::endl;
	}
}

int main(int argc, char* argv[])
{
	ENABLE_LOG(TRUE);
	SET_LOG_OUT(SHOW_MESSAGE);
	SET_LOG_LEVEL(LOG_CRITICAL);

	wsocket_global_startup();

	TEST_SOCKS5_SERVER();
	//TEST_REVERSE_PROXY_SERVER();

	wsocket_global_cleanup();
	return 0;
}
