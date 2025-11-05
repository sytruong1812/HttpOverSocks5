#include <vector>
#include "socks5.h"

namespace NetworkOperations {

	Socks5Client::Socks5Client(const char* server_addr, int server_port, SOCKET_TYPES type, bool enable_ipv6, SOCKS5_RESOLVE resolve)
	{
		_type = type;
		_resolve = resolve;
		_is_ipv6 = enable_ipv6;
		_socks5_serv_addr = _strdup(server_addr);
		_socks5_serv_port = server_port;
		_auth_type = METHODS::NO_AUTHENTICATION_REQUIRED;
		_socket_tcp = std::make_shared<WSocket>();
	}

	Socks5Client::Socks5Client(const char* server_addr, int server_port, const char* username, const char* password, SOCKET_TYPES type, bool enable_ipv6, SOCKS5_RESOLVE resolve)
	{
		_type = type;
		_resolve = resolve;
		_is_ipv6 = enable_ipv6;
		_socks5_serv_addr = _strdup(server_addr);
		_socks5_serv_port = server_port;
		_auth_type = METHODS::NO_AUTHENTICATION_REQUIRED;
		if (username && password)
		{
			_socks5_username = _strdup(username);
			_socks5_password = _strdup(password);
			_auth_type = METHODS::USERNAME_PASSWORD;
		}
		_socket_tcp = std::make_shared<WSocket>();
	}

#ifdef ENABLE_GSSAPI
	Socks5Client::Socks5Client(const char* server_addr, int server_port, const char* service, const char* hostname, const char* security, SOCKET_TYPES type, bool enable_ipv6, SOCKS5_RESOLVE resolve)
	{
		_type = type;
		_resolve = resolve;
		_is_ipv6 = enable_ipv6;
		_socks5_serv_addr = _strdup(server_addr);
		_socks5_serv_port = server_port;
		_auth_type = METHODS::NO_AUTHENTICATION_REQUIRED;
		if (service && hostname)
		{
			_gss = std::make_shared<GSS_CONTEXT>();
			_gss->target_spn = std::string(service) + '/' + std::string(hostname);
			_gss->security_package = security ? security : "Kerberos";
			if (!gss_auth_is_gssapi_supported(_gss->security_package.c_str()))
			{
				LOG_ERROR_A("[GSS-API] SSPI could not get auth info!");
			}
			else
			{
				SECURITY_STATUS status = AcquireCredentialsHandle(NULL,
											(TCHAR*)TEXT(_gss->security_package.c_str()),
											SECPKG_CRED_OUTBOUND,
											NULL,
											NULL,
											NULL,
											NULL,
											&_gss->cred_handle,
											&_gss->expiry_time);
				if (status != SEC_E_OK)
				{
					LOG_ERROR_A("[GSS-API] AcquireCredentialsHandle failed!");
				}
				_auth_type = METHODS::GSS_API;
			}
		}
		_socket_tcp = std::make_shared<SocketClient>();
	}
#endif /* ENABLE_GSSAPI */

	Socks5Client::~Socks5Client()
	{
		disconnect();

		if (_socks5_serv_addr != nullptr)
			free(_socks5_serv_addr);
		if (_destination_addr != nullptr)
			free(_destination_addr);
		if (_socks5_username != nullptr)
			free(_socks5_username);
		if (_socks5_password != nullptr)
			free(_socks5_password);
	}

	void* Socks5Client::get_socket() const
	{
		return _socket_tcp->get_socket();
	}

	int Socks5Client::connect(const char* dst_addr, int dst_port)
	{
		_is_connected = false;
		this->_destination_port = dst_port;
		this->_destination_addr = _strdup(dst_addr);

		if (_type == SOCKET_TYPES::TCP_STREAM && (!dst_addr || dst_port <= 0))
		{
			return ERROR_INVALID_PARAM;
		}
		//step1: SOCKS5 Connect Proxy Server
		if (_socket_tcp->connect(this->_socks5_serv_addr, this->_socks5_serv_port) != SOCKET_OK)
		{
			return ERROR_CONNECTION;
		}
		//step2: SOCKS5 Greeting
		if (client_greeting() != SOCKS5_OK)
		{
			LOG_ERROR_A("[SOCKS5] Handshake -> client_greeting() error!");
			return ERROR_GREETING;
		}
		//step3: SOCKS5 Choose Authentication Mode
		switch (_auth_type)
		{
			case METHODS::NO_AUTHENTICATION_REQUIRED:
			break;
			case METHODS::USERNAME_PASSWORD:
			{
				if (client_auth_handler() != SOCKS5_OK)
				{
					LOG_ERROR_A("[SOCKS5] Handshake -> client_auth_handler() error!");
					return ERROR_AUTH_HANDLE;
				}
			}
			break;
			case METHODS::GSS_API:
			{
#ifdef ENABLE_GSSAPI
				if (client_gss_handler() != SOCKS5_OK)
				{
					LOG_ERROR_A("[SOCKS5] Handshake -> client_gss_handler() error!");
					return ERROR_GSS_HANDLE;
				}
#else 
				LOG_ERROR_A("Unsupported method: GSS-API");
				return SOCKS5_UNSUPORT;
#endif /* ENABLE_GSSAPI */
			}
			break;
			default:
			{
				LOG_ERROR_A("Unsupported method: GSS-API");
				return SOCKS5_UNSUPORT;
			}
			break;
		}	
		//step4: SOCKS5 Send Connection Request 
		int result = client_connection_request(&this->_bound_addr, &this->_bound_port);
		if (result != (int)REPLY::SUCCEEDED)
		{
			LOG_ERROR_A("[SOCKS5] Handshake -> client_connection_request() error, server reply = %d", result);
			return ERROR_CONNECTION_REQUEST;
		}
		
		LOG_INFO_A("[SOCKS5] Handshake done!");
		_is_connected = true;
		return SOCKS5_OK;
	}

	int Socks5Client::tcp_send_data(const char* data, int len)
	{
		int bytes_sent = 0;
		if (!data || len <= 0)
		{
			return ERROR_INVALID_PARAM;
		}
		if (_type != SOCKET_TYPES::TCP_STREAM)
		{
			return ERROR_INTERNAL;
		}
		if (_auth_type == METHODS::GSS_API)
		{
#ifdef ENABLE_GSSAPI
			/*
				+------+------+------+.......................+
				+ VER  | MTYP | LEN  |   TOKEN               |
				+------+------+------+.......................+
				+ 0x01 | 0x01 | 0x02 | up to 2^16 - 1 octets |
				+------+------+------+.......................+

				- "len" is the length of the "token" field in octets
				- "token" is the user data encapsulated by GSS-API
			*/

			std::vector<char> gss_message_protect;
			{
				gss_message_protect.push_back(static_cast<char>(0x01));
				gss_message_protect.push_back(static_cast<char>(_gss->protect_level));
				if (_gss->protect_level == GSS_MESSAGE_PROTECT_LEVEL::LEVEL_1)
				{
					// TOKEN = message + signature
					int signature_size = 0;
					void* signature = nullptr;
					if (gss_make_signature(data, len, &signature, &signature_size) != SOCKS5_OK)
					{
						return ERROR_GSS_SIGN_MESSAGE;
					}
					if (!signature || signature_size == 0)
					{
						return ERROR_GSS_SIGN_MESSAGE;
					}
					int token_size = len + signature_size;
					gss_message_protect.push_back(static_cast<char>(token_size << 8));
					gss_message_protect.push_back(static_cast<char>(token_size));
					gss_message_protect.insert(gss_message_protect.end(), data, data + len);
					gss_message_protect.insert(gss_message_protect.end(), (char*)(signature), (char*)(signature) + signature_size);
					delete[] signature;
				}
				else if (_gss->protect_level == GSS_MESSAGE_PROTECT_LEVEL::LEVEL_2)
				{
					// TOKEN = message encrypted
					int data_encrypted_size = 0;
					void* data_encrypted = nullptr;
					if (gss_encrypt_message(data, len, &data_encrypted, &data_encrypted_size) != SOCKS5_OK)
					{
						return ERROR_GSS_ENCRYPT_MESSAGE;
					}
					if (!data_encrypted || data_encrypted_size == 0)
					{
						return ERROR_GSS_SIGN_MESSAGE;
					}
					gss_message_protect.push_back(static_cast<char>(data_encrypted_size << 8));
					gss_message_protect.push_back(static_cast<char>(data_encrypted_size));
					gss_message_protect.insert(gss_message_protect.end(), (char*)(data_encrypted), (char*)(data_encrypted) + data_encrypted_size);
					delete[] data_encrypted;
				}
				else
				{
					LOG_ERROR_A("[GSS-API] Unsupported level: %d", (int)_gss->protect_level);
					return SOCKS5_UNSUPORT;
				}
			}
			bytes_sent = _socket_tcp->tcp_send_data(gss_message_protect.data(), (int)gss_message_protect.size());
			if (bytes_sent == ERROR_TCP_SEND)
			{
				return ERROR_TCP_SEND;
			}
			return bytes_sent;

#else 
			return SOCKS5_UNSUPORT;
#endif /* ENABLE_GSSAPI */
		}
		else
		{
			bytes_sent = _socket_tcp->tcp_send_data(data, len);
			if (bytes_sent == ERROR_TCP_SEND)
			{
				return ERROR_TCP_SEND;
			}
		}
		return bytes_sent;
	}

	int Socks5Client::tcp_recv_data(char* data, int len)
	{
		int bytes_received = 0;
		if (_type != SOCKET_TYPES::TCP_STREAM)
		{
			return ERROR_INTERNAL;
		}
		if (_auth_type == METHODS::GSS_API)
		{
#ifdef ENABLE_GSSAPI
			/*
				+------+------+------+.......................+
				+ VER  | MTYP | LEN  |   TOKEN               |
				+------+------+------+.......................+
				+ 0x01 | 0x01 | 0x02 | up to 2^16 - 1 octets |
				+------+------+------+.......................+

				- "len" is the length of the "token" field in octets
				- "token" is the user data encapsulated by GSS-API
			*/
			size_t offset = 0;
			std::vector<char> buffer(len);
			bytes_received = _socket_tcp->tcp_receive_data(buffer.data(), (int)buffer.size());
			if (bytes_received < 0)
			{
				return bytes_received;
			}
			if (bytes_received < 4)
			{
				return SOCKS5_ERROR_PARSE;
			}
			char ver = buffer[offset];
			if (ver != 0x01)
			{
				return SOCKS5_ERROR_PARSE;
			}
			char mtyp = buffer[offset + 1];
			if (mtyp == static_cast<char>(GSS_MESSAGE_PROTECT_LEVEL::LEVEL_1))
			{		
				//TODO: Parse get message and signature using for verify data
				int signature_size = 0;
				char* signature_ptr = nullptr;

				// TOKEN = message + signature
				if (gss_verify_signature(buffer.data(), (int)buffer.size(), signature_ptr, signature_size) != SOCKS5_OK)
				{
					return ERROR_GSS_VERIFY_MESSAGE;
				}
			}
			else if (mtyp == static_cast<char>(GSS_MESSAGE_PROTECT_LEVEL::LEVEL_2))
			{
				// TOKEN = message encrypted
				int out_size = 0;
				void* output = nullptr;
				if (gss_decrypt_message(buffer.data(), (int)buffer.size(), &output, &out_size) != SOCKS5_OK)
				{
					return ERROR_GSS_DECRYPT_MESSAGE;
				}
				if (!output)
				{
					return ERROR_GSS_DECRYPT_MESSAGE;
				}
				if (out_size > len)
				{
					return ERROR_BUFFER_TOO_SMALL;
				}
				std::memcpy(data, output, out_size);
				delete[] output;
			}
			else
			{
				LOG_ERROR_A("[GSS-API] Unsupported level: %d", (int)_gss->protect_level);
				return SOCKS5_UNSUPORT;
			}
#else 
			return SOCKS5_UNSUPORT;
#endif /* ENABLE_GSSAPI */
		}
		else
		{
			bytes_received = _socket_tcp->tcp_recv_data(data, len);
			if (bytes_received == ERROR_TCP_RECV)
			{
				return ERROR_TCP_RECV;
			}
		}
		return bytes_received;
	}

	int Socks5Client::tcp_send_timeout(const char* data, int len, unsigned int time_msec)
	{
		if (_type != SOCKET_TYPES::TCP_STREAM)
		{
			return ERROR_INTERNAL;
		}
		int bytes_sented = _socket_tcp->tcp_send_timeout(data, len, time_msec);
		if (bytes_sented == ERROR_TCP_SEND || bytes_sented == ERROR_INTERNAL)
		{
			return ERROR_TCP_SEND;
		}
		return bytes_sented;
	}

	int Socks5Client::tcp_recv_timeout(char* data, int len, unsigned int time_msec)
	{
		if (_type != SOCKET_TYPES::TCP_STREAM)
		{
			return ERROR_INTERNAL;
		}
		int bytes_received = _socket_tcp->tcp_recv_timeout(data, len, time_msec);
		if (bytes_received == ERROR_TCP_RECV || bytes_received == ERROR_INTERNAL)
		{
			return ERROR_TCP_RECV;
		}
		return bytes_received;
	}

	int Socks5Client::tcp_send_data_select_based(const char* data, int len)
	{
		if (_type != SOCKET_TYPES::TCP_STREAM)
		{
			return ERROR_INTERNAL;
		}
		int bytes_sented = _socket_tcp->tcp_send_data_select_based(data, len);
		if (bytes_sented == ERROR_TCP_SEND || bytes_sented == ERROR_INTERNAL)
		{
			return ERROR_TCP_SEND;
		}
		return bytes_sented;
	}

	int Socks5Client::tcp_recv_data_select_based(char* data, int len)
	{
		if (_type != SOCKET_TYPES::TCP_STREAM)
		{
			return ERROR_INTERNAL;
		}
		int bytes_received = _socket_tcp->tcp_recv_data_select_based(data, len);
		if (bytes_received == ERROR_TCP_RECV || bytes_received == ERROR_INTERNAL)
		{
			return ERROR_TCP_RECV;
		}
		return bytes_received;
	}

	int Socks5Client::udp_send_to(const char* dest_addr, int dest_port, const char* data, int len)
	{
		if (dest_addr == nullptr || dest_port <= 0 || data == nullptr || len <= 0)
		{
			return ERROR_INVALID_PARAM;
		}
		std::vector<char> udp_packet;
		{
			/*
				+----+------+------+----------+----------+----------+
				|RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
				+----+------+------+----------+----------+----------+
				| 2  |  1   |  1   | Variable |    2     | Variable |
				+----+------+------+----------+----------+----------+
			*/
			udp_packet.push_back(static_cast<char>(0x00));
			udp_packet.push_back(static_cast<char>(0x00));
			udp_packet.push_back(static_cast<char>(0x00)); // FRAG = 0 (standalone, not fragmented)
			if (_is_ipv6)
			{
				char ipv6_buffer[16] = {};
				if (inet_pton(AF_INET6, _destination_addr, ipv6_buffer) != 1)
				{
					LOG_ERROR_A("Invalid destination IPv6 address: %s", _destination_addr);
					return ERROR_INTERNAL;
				}
				udp_packet.push_back(static_cast<char>(ADDRESS_TYPE::IPV6));
				udp_packet.insert(udp_packet.end(), ipv6_buffer, ipv6_buffer + 16);
			}
			else
			{
				char ipv4_buffer[4] = {};
				if (inet_pton(AF_INET, _destination_addr, ipv4_buffer) != 1)
				{
					LOG_ERROR_A("Invalid destination IPv4 address: %s", _destination_addr);
					return ERROR_INTERNAL;
				}
				udp_packet.push_back(static_cast<char>(ADDRESS_TYPE::IPV4));
				udp_packet.insert(udp_packet.end(), ipv4_buffer, ipv4_buffer + 4);
			}
			udp_packet.push_back(static_cast<char>(_destination_port >> 8));
			udp_packet.push_back(static_cast<char>(_destination_port));
			udp_packet.insert(udp_packet.end(), data, data + len);
		}
		return _socket_udp->udp_send_to(_socks5_serv_addr, _socks5_serv_port, udp_packet.data(), (int)udp_packet.size());
	}

	int Socks5Client::udp_recv_from(char** sender_addr, int* sender_port, char* data, int len)
	{
		if (sender_addr == nullptr || sender_port == nullptr || data == nullptr || len <= 0)
		{
			return ERROR_INVALID_PARAM;
		}
		int offset = 0;
		int bytes_received = 0;
		std::vector<char> buffer(len);
		if ((bytes_received = _socket_udp->udp_recv_from(sender_addr, sender_port, buffer.data(), (int)buffer.size())) < 0)
		{
			return bytes_received;
		}
		/*
			+----+------+------+----------+----------+----------+
			|RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
			+----+------+------+----------+----------+----------+
			| 2  |  1   |  1   | Variable |    2     | Variable |
			+----+------+------+----------+----------+----------+
		*/
		if (bytes_received < 4)
		{
			return SOCKS5_ERROR_PARSE;
		}
		// step 1: Get reserved bytes
		uint16_t rsv = (uint8_t)buffer[offset] << 8 | (uint8_t)buffer[offset + 1];
		if (rsv != 0)
		{
			return SOCKS5_ERROR_PARSE;
		}
		offset += 2;
		// step 2: Get fragmentation (standalone, not fragmented)
		uint8_t frag = buffer[offset];
		if (frag != 0)
		{
			return SOCKS5_ERROR_PARSE;
		}
		offset += 1;
		// step 3: Get address type
		std::unique_ptr<char[]> address = nullptr;
		switch ((uint8_t)buffer[offset])
		{
			case static_cast<char>(ADDRESS_TYPE::IPV4):
			{
				offset += 1;
				if (offset + 4 + 2 > bytes_received)
				{
					return SOCKS5_ERROR_PARSE;
				}
				address = std::make_unique<char[]>(INET_ADDRSTRLEN);
				if (!address)
				{
					return ERROR_ALLOCATING_MEMORY;
				}
				inet_ntop(AF_INET, buffer.data() + offset, address.get(), INET_ADDRSTRLEN);
				offset += 4;
				break;
			}
			case static_cast<char>(ADDRESS_TYPE::DOMAIN_NAME):
			{
				offset += 1;
				uint8_t domain_len = buffer[offset++];
				if (offset + domain_len + 2 > bytes_received)
				{
					return SOCKS5_ERROR_PARSE;
				}
				address = std::make_unique<char[]>(domain_len);
				if (!address)
				{
					return ERROR_ALLOCATING_MEMORY;
				}
				std::memcpy(address.get(), buffer.data() + offset, domain_len);
				offset += domain_len;
				break;
			}
			case static_cast<char>(ADDRESS_TYPE::IPV6):
			{
				offset += 1;
				if (offset + 16 + 2 > bytes_received)
				{
					return SOCKS5_ERROR_PARSE;
				}
				address = std::make_unique<char[]>(INET6_ADDRSTRLEN);
				if (!address)
				{
					return ERROR_ALLOCATING_MEMORY;
				}
				inet_ntop(AF_INET6, buffer.data() + offset, address.get(), INET6_ADDRSTRLEN);
				offset += 16;
				break;
			}
			default:
				return SOCKS5_UNSUPORT;
		}
		// step 5: Get port
		uint16_t port = (uint8_t)buffer[offset] << 8 | (uint8_t)buffer[offset + 1];
		offset += 2;
		// step 6: Get data
		int dataLen = bytes_received - offset;
		if (dataLen > len)
		{
			return ERROR_BUFFER_TOO_SMALL;
		}
		std::memcpy(data, buffer.data() + offset, dataLen);
		if (sender_addr != nullptr && sender_port != nullptr)
		{
			*sender_addr = _strdup(address.get());
			*sender_port = port;
		}
		return (int)dataLen;
	}

	void Socks5Client::shutdown(int how)
	{
		_socket_tcp->shutdown(how);
	}

	void Socks5Client::disconnect()
	{
		if (_socket_tcp)
		{
			_socket_tcp->disconnect();
			_is_connected = false;
		}
	}

	int Socks5Client::client_greeting()
	{
		/*
			+----+----------+----------+
			|VER | NMETHODS | METHODS  |
			+----+----------+----------+
			| 1  |    1     | 1 to 255 |
			+----+----------+----------+
		*/
		std::vector<char> client_greeting_msg;
		{
			client_greeting_msg.push_back(static_cast<char>(VERSION::SOCKS5));
			client_greeting_msg.push_back(static_cast<char>(0x01));
			client_greeting_msg.push_back(static_cast<char>(_auth_type));
		}
		if (_socket_tcp->tcp_send_data(client_greeting_msg.data(), (int)client_greeting_msg.size()) == ERROR_TCP_SEND)
		{
			return ERROR_TCP_SEND;
		}
		/*
			+----+--------+
			|VER | METHOD |
			+----+--------+
			| 1  |   1    |
			+----+--------+
		*/
		std::vector<char> server_choice(2);
		if (_socket_tcp->tcp_recv_data(server_choice.data(), (int)server_choice.size()) == ERROR_TCP_RECV)
		{
			return ERROR_TCP_RECV;
		}
		if (server_choice.at(0) == static_cast<char>(VERSION::SOCKS5))
		{
			if (server_choice.at(1) == static_cast<char>(_auth_type))
			{
				return SOCKS5_OK;
			}
		}
		return ERROR_GREETING;
	}

	int Socks5Client::client_gss_handler()
	{
#ifdef ENABLE_GSSAPI
		// GSS-API Security Context Establishment
		BOOL first_iteration = TRUE;
		std::vector<char> server_token;
		SECURITY_STATUS status = SEC_E_OK;
		do
		{
			SecBuffer in_buffer;
			in_buffer.BufferType = SECBUFFER_TOKEN;
			in_buffer.cbBuffer = (unsigned long)server_token.size();
			in_buffer.pvBuffer = server_token.empty() ? NULL : server_token.data();

			SecBufferDesc in_buffer_desc;
			in_buffer_desc.ulVersion = SECBUFFER_VERSION;
			in_buffer_desc.cBuffers = 1;
			in_buffer_desc.pBuffers = &in_buffer;

			SecBuffer out_buffer;
			out_buffer.BufferType = SECBUFFER_TOKEN;
			out_buffer.cbBuffer = 0;
			out_buffer.pvBuffer = NULL;

			SecBufferDesc out_buffer_desc;
			out_buffer_desc.ulVersion = SECBUFFER_VERSION;
			out_buffer_desc.cBuffers = 1;
			out_buffer_desc.pBuffers = &out_buffer;

			TimeStamp expiry;
			unsigned long context_attr = 0;
			SECURITY_STATUS status = InitializeSecurityContextA(&_gss->cred_handle,
																first_iteration ? NULL : &_gss->ctxt_handle,
																(SEC_CHAR*)_gss->target_spn.c_str(),
																ISC_REQ_MUTUAL_AUTH | ISC_REQ_CONFIDENTIALITY,
																0,
																SECURITY_NATIVE_DREP,
																&in_buffer_desc,
																0,
																first_iteration ? NULL : &_gss->ctxt_handle,
																&out_buffer_desc,
																&context_attr,
																&expiry);
			if (status != SEC_E_OK)
			{
				LOG_ERROR_A("[GSS-API] InitializeSecurityContext failed!");
				if (out_buffer.pvBuffer)
				{
					FreeContextBuffer(out_buffer.pvBuffer);
				}
				return ERROR_GSS_HANDLE;
			}
			else
			{
				first_iteration = FALSE;
			}
			/*
				+------+------+------+.......................+
				+ VER  | MTYP | LEN  |       TOKEN           |
				+------+------+------+.......................+
				+ 0x01 | 0x01 | 0x02 | up to 2^16 - 1 octets |
				+------+------+------+.......................+
			*/
			unsigned long client_token_len = out_buffer.cbBuffer;
			char* client_token_ptr = (char*)out_buffer.pvBuffer;
			std::vector<char> client_gss_request;
			{
				client_gss_request.push_back(static_cast<char>(0x01));
				client_gss_request.push_back(static_cast<char>(0x01));
				client_gss_request.push_back(static_cast<char>(client_token_len >> 8));
				client_gss_request.push_back(static_cast<char>(client_token_len));
				client_gss_request.insert(client_gss_request.end(), client_token_ptr, client_token_ptr + client_token_len);
			}
			if (_socket_tcp->tcp_send_data(client_gss_request.data(), (int)client_gss_request.size()) == ERROR_TCP_SEND)
			{
				if (out_buffer.pvBuffer)
				{
					FreeContextBuffer(out_buffer.pvBuffer);
				}
				return ERROR_TCP_SEND;
			}
			if (out_buffer.pvBuffer)
			{
				FreeContextBuffer(out_buffer.pvBuffer);
			}
			/*
				+------+------+
				+ VER  | MTYP |
				+------+------+
				+ 0x01 | 0xFF |
				+------+------+
			*/
			std::vector<char> server_gss_response(1 + 1);
			if (_socket_tcp->tcp_receive_data(server_gss_response.data(), (int)server_gss_response.size()) == ERROR_TCP_RECV)
			{
				return ERROR_TCP_RECV;
			}
			if (server_gss_response.at(0) != 0x01)
			{
				return ERROR_GSS_HANDLE;
			}
			if (server_gss_response.at(1) == 0xFF)
			{
				return ERROR_GSS_HANDLE;
			}
			/*
				+------+.......................+
				| LEN  |       TOKEN           |
				+------+.......................+
				| 0x02 | up to 2^16 - 1 octets |
				+------+.......................+
			*/
			std::vector<char> server_gss_token(2 + out_buffer.cbBuffer);
			if (_socket_tcp->tcp_receive_data(server_gss_token.data(), (int)server_gss_token.size()) == ERROR_TCP_RECV)
			{
				return ERROR_TCP_RECV;
			}
			unsigned long server_token_len = (unsigned char(server_gss_token[0]) << 8) | (unsigned char(server_gss_token[1]));
			server_token.resize(server_token_len);
			memcpy(server_token.data(), server_gss_token.data() + 2, server_token_len);
		} while (status == SEC_I_CONTINUE_NEEDED);
		return SOCKS5_OK;
#else 
		return SOCKS5_UNSUPORT;
#endif /* ENABLE_GSSAPI */
	}

	int Socks5Client::client_auth_handler()
	{
		/*
			+----+------+----------+------+----------+
			|VER | ULEN |  UNAME   | PLEN |  PASSWD  |
			+----+------+----------+------+----------+
			| 1  |  1   | 1 to 255 |  1   | 1 to 255 |
			+----+------+----------+------+----------+
		*/
		std::vector<char> client_auth_request;
		{
			client_auth_request.push_back(static_cast<char>(0x01));
			client_auth_request.push_back(static_cast<char>(strlen(this->_socks5_username)));
			for (size_t i = 0; i < strlen(this->_socks5_username); i++)
			{
				client_auth_request.push_back(this->_socks5_username[i]);
			}
			client_auth_request.push_back(static_cast<char>(strlen(this->_socks5_password)));
			for (size_t i = 0; i < strlen(this->_socks5_password); i++)
			{
				client_auth_request.push_back(this->_socks5_password[i]);
			}
		}
		if (_socket_tcp->tcp_send_data(client_auth_request.data(), (int)client_auth_request.size()) == ERROR_TCP_SEND)
		{
			return ERROR_TCP_SEND;
		}
		/*
			+----+--------+
			|VER | STATUS |
			+----+--------+
			| 1  |   1    |
			+----+--------+
			VER: The field contains the current version of the subnegotiation, which is X'01'
		*/
		std::vector<char> server_auth_response(2);
		if (_socket_tcp->tcp_recv_data(server_auth_response.data(), (int)server_auth_response.size()) == ERROR_TCP_RECV)
		{
			return ERROR_TCP_RECV;
		}
		return (server_auth_response.at(0) == 0x01 && server_auth_response.at(1) == 0x00) ? SOCKS5_OK : ERROR_AUTH_HANDLE;
	}

	int Socks5Client::client_connection_request(char** bnd_addr, int* bnd_port)
	{
		std::vector<char> connection_request;
		{
			/*
				+----+-----+-------+------+----------+----------+
				|VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
				+----+-----+-------+------+----------+----------+
				| 1  |  1  | X'00' |  1   | Variable |    2     |
				+----+-----+-------+------+----------+----------+
			*/
			connection_request.push_back(static_cast<char>(VERSION::SOCKS5));
			if (_type == SOCKET_TYPES::UDP_DATAGRAM)
			{
				connection_request.push_back(static_cast<char>(COMMAND::UDP_ASSOCIATE));
				_socket_udp = std::make_shared<WSocket>(SOCKET_TYPES::UDP_DATAGRAM);
			}
			else
			{
				connection_request.push_back(static_cast<char>(COMMAND::CONNECT));
			}
			connection_request.push_back(static_cast<char>(0x00));

			if (_resolve == SOCKS5_RESOLVE::LOCAL_RESOLVE)
			{
				char* ip_resolve = nullptr;
				if (!dns_local_resolve(this->_destination_addr, _is_ipv6, &ip_resolve) || !ip_resolve)
				{
					LOG_ERROR_A("Failed to resolve address: %s", _destination_addr);
					return ERROR_INTERNAL;
				}
				if (ip_resolve)
				{
					this->_destination_addr = _strdup(ip_resolve);
					delete[] ip_resolve;
				}
				if (_is_ipv6)
				{
					char ipv6_buffer[16] = {};
					if (inet_pton(AF_INET6, _destination_addr, ipv6_buffer) != 1)
					{
						LOG_ERROR_A("Invalid destination IPv6 address: %s", _destination_addr);
						return ERROR_INTERNAL;
					}
					connection_request.push_back(static_cast<char>(ADDRESS_TYPE::IPV6));
					connection_request.insert(connection_request.end(), ipv6_buffer, ipv6_buffer + 16);
				}
				else
				{
					char ipv4_buffer[4] = {};
					if (inet_pton(AF_INET, _destination_addr, ipv4_buffer) != 1)
					{
						LOG_ERROR_A("Invalid destination IPv4 address: %s", _destination_addr);
						return ERROR_INTERNAL;
					}
					connection_request.push_back(static_cast<char>(ADDRESS_TYPE::IPV4));
					connection_request.insert(connection_request.end(), ipv4_buffer, ipv4_buffer + 4);
				}
			}
			else
			{
				connection_request.push_back(static_cast<char>(ADDRESS_TYPE::DOMAIN_NAME));
				connection_request.push_back(static_cast<char>(strlen(this->_destination_addr)));
				for (std::size_t i = 0; i < strlen(this->_destination_addr); i++)
				{
					connection_request.push_back(this->_destination_addr[i]);
				}
			}
			connection_request.push_back(static_cast<char>(this->_destination_port >> 8));
			connection_request.push_back(static_cast<char>(this->_destination_port));
		}
		if (_socket_tcp->tcp_send_data(connection_request.data(), (int)connection_request.size()) == ERROR_TCP_SEND)
		{
			return ERROR_TCP_SEND;
		}
		/*
			+----+-----+-------+------+----------+----------+
			|VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
			+----+-----+-------+------+----------+----------+
			| 1  |  1  | X'00' |  1   | Variable |    2     |
			+----+-----+-------+------+----------+----------+
		*/
		int reply = 0;
		int offset = 0;
		int bytes_received = 0;
		std::vector<char> connection_response(connection_request.size());
		if ((bytes_received = _socket_tcp->tcp_recv_data(connection_response.data(), (int)connection_response.size())) == ERROR_TCP_RECV)
		{
			return ERROR_TCP_RECV;
		}
		// Protocol version
		if (connection_response.at(offset) != static_cast<char>(VERSION::SOCKS5))
		{
			return ERROR_CONNECTION_REQUEST;
		}
		offset += 1;
		// Reply type
		if ((reply = static_cast<int>(connection_response.at(offset))) != static_cast<char>(REPLY::SUCCEEDED))
		{
			return reply;
		}
		offset += 1;
		// RESERVED must be set to X'00'.
		if (static_cast<int>(connection_response.at(offset)) != 0x00) 
		{
			return ERROR_CONNECTION_REQUEST;
		}
		offset += 1;
		// Address type
		std::unique_ptr<char[]> address;
		switch (connection_response.at(offset))
		{
			case static_cast<char>(ADDRESS_TYPE::IPV4):
			{
				offset += 1;
				if (offset + 4 + 2 > bytes_received)
				{
					return SOCKS5_ERROR_PARSE;
				}
				address = std::make_unique<char[]>(INET_ADDRSTRLEN);
				if (!address)
				{
					return ERROR_ALLOCATING_MEMORY;
				}
				inet_ntop(AF_INET, connection_response.data() + offset, address.get(), INET_ADDRSTRLEN);
				offset += 4;
				break;
			}
			case static_cast<char>(ADDRESS_TYPE::DOMAIN_NAME):
			{
				offset += 1;
				uint8_t domain_len = connection_response[offset++];
				if (offset + domain_len + 2 > bytes_received)
				{
					return SOCKS5_ERROR_PARSE;
				}
				address = std::make_unique<char[]>(domain_len);
				if (!address)
				{
					return ERROR_ALLOCATING_MEMORY;
				}
				std::memcpy(address.get(), connection_response.data() + offset, domain_len);
				offset += domain_len;
				break;
			}
			case static_cast<char>(ADDRESS_TYPE::IPV6):
			{
				offset += 1;
				if (offset + 16 + 2 > bytes_received)
				{
					return SOCKS5_ERROR_PARSE;
				}
				address = std::make_unique<char[]>(INET6_ADDRSTRLEN);
				if (!address)
				{
					return ERROR_ALLOCATING_MEMORY;
				}
				inet_ntop(AF_INET6, connection_response.data() + offset, address.get(), INET6_ADDRSTRLEN);
				offset += 16;
				break;
			}
			default:
				return SOCKS5_UNSUPORT;
		}
		// step 5: Get port
		uint16_t port = (uint8_t)connection_response[offset] << 8 | (uint8_t)connection_response[offset + 1];
		offset += 2;

		if (bnd_addr != nullptr && bnd_port != nullptr)
		{
			*bnd_port = port;
			*bnd_addr = _strdup(address.get());
		}
		return reply;
	}

#ifdef ENABLE_GSSAPI
	bool Socks5Client::gss_auth_is_gssapi_supported(const void* security_package)
	{
		PSecPkgInfo SecurityPackage;
		SECURITY_STATUS status = QuerySecurityPackageInfo((TCHAR*)TEXT(security_package), &SecurityPackage);
		if (status == SEC_E_OK)
		{
			FreeContextBuffer(SecurityPackage);
		}
		return (status == SEC_E_OK);
	}

	int Socks5Client::gss_make_signature(const void* data, int data_size, void** sign, int* sign_size)
	{
		ULONG fQOP = 0;
		SECURITY_STATUS status;
		SecPkgContext_Sizes ctx_size;
		SecBufferDesc InputBufferDescriptor;
		SecBuffer InputToken[2];
		if (!data || data_size <= 0 || !sign || !sign_size)
		{
			return ERROR_INVALID_PARAM;
		}
		if (QueryContextAttributes(&_gss->ctxt_handle, SECPKG_ATTR_SIZES, &ctx_size) != SEC_E_OK)
		{
			LOG_ERROR_A("[GSS-API] Failed to query context attributes.");
			return ERROR_GSS_SIGN_MESSAGE;
		}
		if (ctx_size.cbMaxSignature == 0)
		{
			LOG_ERROR_A("[GSS-API] This session does not support message signing.");
			return ERROR_GSS_SIGN_MESSAGE;
		}
		//-------------------------------------------------------------------
		// Build the buffer descriptor and the buffers to pass to the MakeSignature call.
		InputBufferDescriptor.ulVersion = SECBUFFER_VERSION;
		InputBufferDescriptor.cBuffers = 2;
		InputBufferDescriptor.pBuffers = InputToken;

		//-------------------------------------------------------------------
		// Build a security buffer for the message itself. 
		InputToken[0].BufferType = SECBUFFER_DATA;
		InputToken[0].cbBuffer = data_size;
		InputToken[0].pvBuffer = (void*)data;

		//-------------------------------------------------------------------
		// Allocate and build a security buffer for the message signature.
		InputToken[1].BufferType = SECBUFFER_TOKEN;
		InputToken[1].cbBuffer = ctx_size.cbMaxSignature;
		InputToken[1].pvBuffer = (void*)malloc(ctx_size.cbMaxSignature);

		status = MakeSignature(&_gss->ctxt_handle, fQOP, &InputBufferDescriptor, 0);
		if (status != SEC_E_OK)
		{
			LOG_ERROR_A("[GSS-API] MakeSignature returned error!");
			free(InputToken[1].pvBuffer);
			return ERROR_GSS_SIGN_MESSAGE;
		}
		*sign_size = (int)ctx_size.cbMaxSignature;
		*sign = new char[ctx_size.cbMaxSignature];
		if (!*sign)
		{
			return ERROR_ALLOCATING_MEMORY;
		}
		std::memcpy(*sign, InputToken[1].pvBuffer, InputToken[1].cbBuffer);
		free(InputToken[1].pvBuffer);
		return SOCKS5_OK;
	}

	int Socks5Client::gss_verify_signature(const void* data, int data_size, const void* sign, int sign_size)
	{
		ULONG fQOP = 0;
		SECURITY_STATUS status;
		SecBufferDesc InputBufferDescriptor;
		SecBuffer InputToken[2];
		if (!data || data_size <= 0 || !sign || sign_size <= 0)
		{
			return ERROR_INVALID_PARAM;
		}
		//-------------------------------------------------------------------
		// Build the input buffer descriptor.
		InputBufferDescriptor.ulVersion = SECBUFFER_VERSION;
		InputBufferDescriptor.cBuffers = 2;
		InputBufferDescriptor.pBuffers = InputToken;

		//-------------------------------------------------------------------
		// Build the security buffer for the message.
		InputToken[0].BufferType = SECBUFFER_DATA;
		InputToken[0].cbBuffer = data_size;
		InputToken[0].pvBuffer = (void*)data;

		//-------------------------------------------------------------------
		// Build the security buffer for the signature.
		InputToken[1].BufferType = SECBUFFER_TOKEN;
		InputToken[1].cbBuffer = sign_size;
		InputToken[1].pvBuffer = (void*)sign;

		status = VerifySignature(&_gss->ctxt_handle, &InputBufferDescriptor, 0, &fQOP);
		if (status == SEC_E_OK)
		{
			LOG_ERROR_A("[GSS-API] The signature verified the message.");
		}
		else
		{
			if (status == SEC_E_MESSAGE_ALTERED)
			{
				LOG_ERROR_A("[GSS-API] The message was altered in transit.");
			}
			else
			{
				if (status == SEC_E_OUT_OF_SEQUENCE)
				{
					LOG_ERROR_A("[GSS-API] The message is out of sequence.");
				}
				else
				{
					LOG_ERROR_A("[GSS-API] An unknown error occurred in VerifyMessage.");
				}
			}
			return ERROR_GSS_VERIFY_MESSAGE;
		}
		return SOCKS5_OK;
	}

	int Socks5Client::gss_encrypt_message(const void* data_in, int data_in_size, void** data_out, int* data_out_size)
	{
		ULONG fQOP = 0;
		SECURITY_STATUS status;
		SecPkgContext_StreamSizes ctx_stream_size;
		SecBufferDesc InputBufferDescriptor;
		SecBuffer InputToken[4];
		if (!data_in || data_in_size <= 0 || !data_out || !data_out_size)
		{
			return ERROR_INVALID_PARAM;
		}
		if (QueryContextAttributes(&_gss->ctxt_handle, SECPKG_ATTR_STREAM_SIZES, &ctx_stream_size) != SEC_E_OK)
		{
			LOG_ERROR_A("[GSS-API] Failed to query context attributes.");
			return ERROR_GSS_SIGN_MESSAGE;
		}
		if (ctx_stream_size.cbMaximumMessage == 0)
		{
			LOG_ERROR_A("[GSS-API] This session does not support message signing.");
			return ERROR_GSS_SIGN_MESSAGE;
		}

		DWORD cbIoBuffer = ctx_stream_size.cbHeader + ctx_stream_size.cbMaximumMessage + ctx_stream_size.cbTrailer;
		PBYTE pbIoBuffer = (BYTE*)malloc(cbIoBuffer);
		if (!pbIoBuffer)
		{
			LOG_ERROR_A("[GSS-API] Out of memory");
			return ERROR_ALLOCATING_MEMORY;
		}

		//-------------------------------------------------------------------
		// Build the input buffer descriptor.
		InputBufferDescriptor.cBuffers = 4;
		InputBufferDescriptor.pBuffers = InputToken;
		InputBufferDescriptor.ulVersion = SECBUFFER_VERSION;
		//-------------------------------------------------------------------
		// [Header][Encrypted Data][Trailer][Empty]
		InputToken[0].BufferType = SECBUFFER_STREAM_HEADER;
		InputToken[0].cbBuffer = cbIoBuffer;
		InputToken[0].pvBuffer = pbIoBuffer;

		InputToken[1].BufferType = SECBUFFER_DATA;
		InputToken[1].cbBuffer = data_in_size;
		InputToken[1].pvBuffer = (void*)data_in;

		InputToken[2].BufferType = SECBUFFER_STREAM_TRAILER;
		InputToken[2].cbBuffer = ctx_stream_size.cbTrailer;
		InputToken[2].pvBuffer = (pbIoBuffer + ctx_stream_size.cbHeader) + data_in_size;

		InputToken[3].BufferType = SECBUFFER_EMPTY;

		status = EncryptMessage(&_gss->ctxt_handle, fQOP, &InputBufferDescriptor, 0);
		if (status != SEC_E_OK)
		{
			LOG_ERROR_A("[GSS-API] EncryptMessage returned error!");
			return ERROR_GSS_ENCRYPT_MESSAGE;
		}
		*data_out_size = cbIoBuffer;
		*data_out = new char[cbIoBuffer];
		if (!*data_out)
		{
			return ERROR_ALLOCATING_MEMORY;
		}
		std::memcpy(*data_out, pbIoBuffer, cbIoBuffer);
		return SOCKS5_OK;
	}

	int Socks5Client::gss_decrypt_message(const void* data_in, int data_in_size, void** data_out, int* data_out_size)
	{
		ULONG fQOP = 0;
		SECURITY_STATUS status;
		SecPkgContext_StreamSizes ctx_stream_size;
		SecBufferDesc InputBufferDescriptor;
		SecBuffer InputToken[4];
		if (!data_in || data_in_size <= 0 || !data_out || !data_out_size)
		{
			return ERROR_INVALID_PARAM;
		}
		if (QueryContextAttributes(&_gss->ctxt_handle, SECPKG_ATTR_STREAM_SIZES, &ctx_stream_size) != SEC_E_OK)
		{
			LOG_ERROR_A("[GSS-API] Failed to query context attributes.");
			return ERROR_GSS_SIGN_MESSAGE;
		}
		if (ctx_stream_size.cbMaximumMessage == 0)
		{
			LOG_ERROR_A("[GSS-API] This session does not support message signing.");
			return ERROR_GSS_SIGN_MESSAGE;
		}

		DWORD cbIoBuffer = ctx_stream_size.cbHeader + ctx_stream_size.cbMaximumMessage + ctx_stream_size.cbTrailer;
		PBYTE pbIoBuffer = (BYTE*)malloc(cbIoBuffer);
		if (!pbIoBuffer)
		{
			LOG_ERROR_A("[GSS-API] Out of memory");
			return ERROR_ALLOCATING_MEMORY;
		}
		//-------------------------------------------------------------------
		// Build the input buffer descriptor.
		InputBufferDescriptor.cBuffers = 4;
		InputBufferDescriptor.pBuffers = InputToken;
		InputBufferDescriptor.ulVersion = SECBUFFER_VERSION;
		//-------------------------------------------------------------------
		// [Encrypted Data][Empty][Empty][Empty]
		InputToken[0].BufferType = SECBUFFER_DATA;
		InputToken[0].cbBuffer = cbIoBuffer;
		InputToken[0].pvBuffer = pbIoBuffer;

		InputToken[1].BufferType = SECBUFFER_EMPTY;
		InputToken[2].BufferType = SECBUFFER_EMPTY;
		InputToken[3].BufferType = SECBUFFER_EMPTY;

		status = DecryptMessage(&_gss->ctxt_handle, &InputBufferDescriptor, 0, &fQOP);
		if (status != SEC_E_OK)
		{
			LOG_ERROR_A("[GSS-API] DecryptMessage returned error!");
			return ERROR_GSS_DECRYPT_MESSAGE;
		}
		// [Header][Encrypted Data][Trailer][Empty]
		for (int i = 0; i < 4; i++)
		{		
			if (InputToken[i].BufferType == SECBUFFER_DATA)
			{
				// Get [Encrypted Data]
				*data_out_size = InputToken[i].cbBuffer;
				*data_out = new char[InputToken[i].cbBuffer];
				if (!*data_out)
				{
					return ERROR_ALLOCATING_MEMORY;
				}
				std::memcpy(*data_out, InputToken[i].pvBuffer, InputToken[i].cbBuffer);
				break;
			}
		}
		return SOCKS5_OK;
	}
#endif /* ENABLE_GSSAPI */

}	// NetworkOperations

