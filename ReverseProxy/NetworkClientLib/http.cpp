#include "http.h"
#include "utils.h"

namespace NetworkOperations 
{
	HttpClient::~HttpClient()
	{
		if (_is_connected)
		{
			Disconnect();
		}
	}

	bool HttpClient::Connect(const std::string& host, int port)
	{
		int status = 0;
		this->_host = host;
		this->_port = port;
		this->_is_connected = true;
		_transport = std::make_shared<WSocket>();
		if ((status = _transport->connect(host.c_str(), port)) != SOCKS5_OK)
		{
			LOG_ERROR_A("HTTP connect failed! Error code = %d.", status);
			this->_is_connected = false;
			return false;
		}
		return true;
	}

	bool HttpClient::ConnectViaSocks5(const std::string& host, int port, const std::string& proxy_host, int proxy_port)
	{
		int status = 0;
		this->_host = host;
		this->_port = port;
		this->_is_connected = true;
		_transport = std::make_shared<Socks5Client>(proxy_host.c_str(), proxy_port);
		if ((status = _transport->connect(host.c_str(), port)) != SOCKS5_OK)
		{
			LOG_ERROR_A("HTTP connect vie SOCKS5 failed! Error code = %d", status);
			this->_is_connected = false;
			return false;
		}
		return true;
	}

	bool HttpClient::ConnectViaSocks5Auth(const std::string& host, int port, const std::string& proxy_host, int proxy_port,
		const std::string& proxy_username, const std::string& proxy_password)
	{
		int status = 0;
		this->_host = host;
		this->_port = port;
		this->_is_connected = true;
		_transport = std::make_shared<Socks5Client>(proxy_host.c_str(), proxy_port, proxy_username.c_str(), proxy_password.c_str());
		if ((status = _transport->connect(host.c_str(), port)) != SOCKS5_OK)
		{
			LOG_ERROR_A("HTTP connect vie SOCKS5 with Auth failed! Error code = %d", status);
			this->_is_connected = false;
			return false;
		}
		return true;
	}

	bool HttpClient::ProcessSendRequest(const std::unique_ptr<Request>& request)
	{
		if (!_is_connected)
		{
			return false;
		}
		if (request->hasHeader("Transfer-Encoding") && request->getHeaderValue("Transfer-Encoding") == "chunked")
		{
			//step1: Send header
			std::string request_header = request->getHeaderString();
			ChunkTransfer::send_data(_transport->get_socket(), request_header);
			ChunkTransfer::send_data(_transport->get_socket(), "\r\n\r\n");

			//step2: Send chunk-size + chunk-data
			std::string body_data = request->getBody();
			ChunkTransfer::send_chunked(_transport->get_socket(), body_data);
		}
		else
		{
			if (_transport->tcp_send_data(request->get_string().c_str(), (int)request->get_size()) <= 0)
			{
				return false;
			}
		}
		return true;
	}

	bool HttpClient::ProcessReadResponse(std::unique_ptr<Response>& response)
	{
		if (!_is_connected)
		{
			return false;
		}
		//step1: Read request header
		std::string response_data;
		do
		{
			std::string line = ChunkTransfer::read_line(_transport->get_socket(), true);
			response_data.append(line);
			if (line.compare("\r\n") == 0)
			{
				break;	// End of header
			}
		}
		while (true);

		response = std::make_unique<Response>(response_data);

		//step2: Get content-length
		int content_length = 0;
		auto response_headers = response->getHeaders();
		if (response_headers.find("Content-Length") != response_headers.end())
		{
			content_length = std::atoi(response_headers["Content-Length"].c_str());
			if (content_length == 0)
			{
				return true;
			}
		}
		//step3: Read request body (Transfer-Encoding with chunked)
		if (response_headers.find("Transfer-Encoding") != response_headers.end() && response_headers["Transfer-Encoding"] == "chunked")
		{
			std::string chunk_data = ChunkTransfer::read_chunked(_transport->get_socket());
			response->setBody(chunk_data);
			//response_data.append(chunk_data);
		}
		else
		{
			auto content_data = std::make_unique<char[]>(content_length);
			if (_transport->tcp_recv_data(content_data.get(), content_length) <= 0)
			{
				return false;
			}
			response->setBody(content_data.get());
			//response_data.append(content_data.get(), content_length);
		}
		return true;
	}

	bool HttpClient::ProcessReadHeaderResponse(PBYTE& header_data, DWORD& header_size)
	{
		if (!_is_connected)
		{
			return false;
		}
		std::string response_header;
		do
		{
			std::string line = ChunkTransfer::read_line(_transport->get_socket(), true);
			response_header.append(line);
			if (line.compare("\r\n") == 0)
			{
				break;	// End of header
			}
		}
		while (true);

		if (header_data)
		{
			header_size = (DWORD)response_header.length();
			header_data = new BYTE[response_header.length()];
			if (!header_data)
			{
				return false;
			}
			::memcpy(header_data, response_header.c_str(), response_header.length());
		}
		return true;
	}

	bool HttpClient::ProcessReadContentResponse(PBYTE& content_data, DWORD& content_size)
	{
		if (!_is_connected)
		{
			return false;
		}
		//step1: Read request header
		std::string response_header;
		do
		{
			std::string line = ChunkTransfer::read_line(_transport->get_socket(), true);
			response_header.append(line);
			if (line.compare("\r\n") == 0)
			{
				break;	// End of header
			}
		}
		while (true);

		//step2: Get content-length
		int content_length = 0;
		auto response_headers = std::make_unique<Response>(response_header, true)->getHeaders();
		if (response_headers.find("Content-Length") != response_headers.end())
		{
			content_length = std::atoi(response_headers["Content-Length"].c_str());
			if (content_length == 0)
			{
				return true;
			}
		}
		//step3: Read request body (Transfer-Encoding with chunked)
		std::string response_data;
		if (response_headers.find("Transfer-Encoding") != response_headers.end() && response_headers["Transfer-Encoding"] == "chunked")
		{
			std::string chunk_data = ChunkTransfer::read_chunked(_transport->get_socket());
			response_data.append(chunk_data);
		}
		else
		{
			auto content_data = std::make_unique<char[]>(content_length);
			if (_transport->tcp_recv_data(content_data.get(), content_length) <= 0)
			{
				return false;
			}
			response_data.append(content_data.get(), content_length);
		}

		content_size = (DWORD)response_data.length();
		content_data = new BYTE[response_data.length()];
		if (!content_data)
		{
			return false;
		}
		::memcpy(content_data, response_data.c_str(), response_data.length());
		
		return true;
	}

	std::unique_ptr<Response> HttpClient::SendRequest(const std::unique_ptr<Request>& request)
	{
		if (!_is_connected)
		{
			return nullptr;
		}
		if (!ProcessSendRequest(request))
		{
			return nullptr;
		}
		std::unique_ptr<Response> response;
		if (!ProcessReadResponse(response))
		{
			return nullptr;
		}
		return response;
	}

	std::unique_ptr<Response> HttpClient::Get(const std::string& path, const Headers& header)
	{
		auto request = std::make_unique<Request>("GET", path, "HTTP/1.1");
		{
			for (auto it : header)
			{
				request->setHeader(it.first, it.second);
			}
			request->setBody("");
		}
		return SendRequest(request);
	}

	std::unique_ptr<Response> HttpClient::Post(const std::string& path, const Headers& header, const std::string& body)
	{
		auto request = std::make_unique<Request>("POST", path, "HTTP/1.1");
		{
			for (auto it : header)
			{
				request->setHeader(it.first, it.second);
			}
			request->setBody(body);
		}
		return SendRequest(request);
	}

	bool HttpClient::UploadFile(const std::string& path, const Headers& header, const std::wstring& input_path)
	{
		if (!Helper::FileHelper::IsFileExists(input_path)) 
		{
			return false;
		}
		std::wstring file_name_w = Helper::PathHelper::extractFileNameFromFilePath(input_path);
		std::string file_name = Helper::StringHelper::convertWideStringToString(file_name_w);
		auto request = std::make_unique<Request>("POST", path, "HTTP/1.1");
		{
			for (auto it : header)
			{
				request->setHeader(it.first, it.second);
			}
			std::string boundary = Helper::CreateUUIDString();
			request->setHeader("Content-Type", "multipart/form-data;boundary=\"" + boundary + "\"");
			std::ostringstream body;
			{
				auto writer = std::make_unique<MultipartWriter>(&body);
				writer->Start(boundary);
				writer->AddFile("sendfile", file_name, input_path);
				writer->Finish();
			}
			request->setBody(body.str());
		}
		auto response = SendRequest(request);
		if (response->getStatus() != 200)
		{
			return false;
		}
		return true;
	}

	bool HttpClient::DownloadFile(const std::string& path, const Headers& header, const std::wstring& output_path)
	{
		auto request = std::make_unique<Request>("GET", path, "HTTP/1.1");
		{
			for (auto it : header)
			{
				request->setHeader(it.first, it.second);
			}
			request->setBody("");
		}
		if (!ProcessSendRequest(request))
		{
			return false;
		}
		DWORD content_size = 0;
		PBYTE content_data = nullptr;
		if (!ProcessReadContentResponse(content_data, content_size))
		{
			return false;
		}
		if (!content_data)
		{
			return false;
		}
		if (!Helper::FileHelper::WriteFileData(output_path, content_data, content_size))
		{
			return false;
		}
		delete[] content_data;
	
		return true;
	}

	void HttpClient::Disconnect()
	{
		if (_transport && _is_connected)
		{
			_transport->disconnect();
			_is_connected = false;
		}
	}

}	// NetworkOperations