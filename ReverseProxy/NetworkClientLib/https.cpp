#include "https.h"
#include "utils.h"

namespace NetworkOperations 
{
	HttpsClient::HttpsClient()
	{
#ifdef ENABLE_MBEDTLS
		_security = std::make_shared<MbedTLS>();
#else
		_security = std::make_shared<SchannelTLS>();
#endif
	}

	HttpsClient::HttpsClient(const std::string& cert_path)
	{
#ifdef ENABLE_MBEDTLS
		_security = std::make_shared<MbedTLS>();
		_security->set_trusted_ca(cert_path.c_str(), nullptr, nullptr);
#else
		_security = std::make_shared<SchannelTLS>();
		_security->set_trusted_ca(cert_path.c_str(), NULL, NULL);
#endif
	}
	HttpsClient::HttpsClient(const std::string& cert_path, const std::string& password, const std::string& subject_name)
	{
#ifdef ENABLE_MBEDTLS
		_security = std::make_shared<MbedTLS>();
		_security->set_trusted_ca(cert_path.c_str(), nullptr, nullptr);
#else
		_security = std::make_shared<SchannelTLS>();
		_security->set_trusted_ca(cert_path.c_str(), password.c_str(), subject_name.c_str());
#endif
	}

	HttpsClient::~HttpsClient()
	{
		if (_is_connected)
		{
			Disconnect();
		}
	}

	bool HttpsClient::Connect(const std::string& host, int port)
	{
		int status = 0;
		this->_host = host;
		this->_port = port;
		this->_is_connected = true;
		_transport = std::make_shared<WSocket>();
		if ((status = _transport->connect(host.c_str(), port)) != SOCKET_OK)
		{
			LOG_ERROR_A("HTTPS connect failed! Error code = %d.", status);
			this->_is_connected = false;
			return false;
		}
		return true;
	}

	bool HttpsClient::ConnectViaSocks5(const std::string& host, int port, const std::string& proxy_host, int proxy_port)
	{
		int status = 0;
		this->_host = host;
		this->_port = port;
		this->_is_connected = true;
		_transport = std::make_shared<Socks5Client>(proxy_host.c_str(), proxy_port);
		if ((status = _transport->connect(host.c_str(), port)) != SOCKS5_OK)
		{
			LOG_ERROR_A("HTTPS connect vie SOCKS5 failed! Error code = %d", status);
			this->_is_connected = false;
			return false;
		}
		return true;
	}

	bool HttpsClient::ConnectViaSocks5Auth(const std::string& host, int port, 
		const std::string& proxy_host, int proxy_port,
		const std::string& proxy_user, const std::string& proxy_pass)
	{
		int status = 0;
		this->_host = host;
		this->_port = port;
		this->_is_connected = true;
		_transport = std::make_shared<Socks5Client>(proxy_host.c_str(), proxy_port, proxy_user.c_str(), proxy_pass.c_str());
		if ((status = _transport->connect(host.c_str(), port)) != SOCKS5_OK)
		{
			LOG_ERROR_A("HTTPS connect vie SOCKS5 with Auth failed! Error code = %d", status);
			this->_is_connected = false;
			return false;
		}
		return true;
	}

	std::unique_ptr<Response> HttpsClient::SendRequest(const std::unique_ptr<Request>& request)
	{
		if (!_is_connected)
		{
			return nullptr;
		}
		if (!_security->initialize(_transport.get()))
		{
			LOG_ERROR_A("SSL initialize failed!");
			return nullptr;
		}
		LOG_INFO_A("SSL initialize... ok!");
		if (!_security->perform_handshake(this->_host.c_str(), false))
		{
			LOG_ERROR_A("SSL handshake... failed!");
			return nullptr;
		}
		LOG_INFO_A("SSL handshake... ok!");
		this->_is_handshake = true;

		int wstatus = _security->write_data(request->get_string().c_str(), (int)request->get_size());
		if (wstatus <= 0)
		{
			LOG_ERROR_A("[!] ssl_write_data returned %d", wstatus);
			return nullptr;
		}
		auto buffer = std::make_unique<char[]>(BUFFER_SIZE);
		int rstatus = _security->read_data(buffer.get(), BUFFER_SIZE);
		if (rstatus <= 0)
		{
			LOG_ERROR_A("[!] ssl_read_data returned %d", rstatus);
			return nullptr;
		}
		return std::make_unique<Response>(buffer.get(), BUFFER_SIZE);
	}

	std::unique_ptr<Response> HttpsClient::Get(const std::string& path, const Headers& header)
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

	std::unique_ptr<Response> HttpsClient::Post(const std::string& path, const Headers& header, const std::string& body)
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

	bool HttpsClient::UploadFile(const std::string& path, const Headers& header, const std::wstring& input_path)
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

	bool HttpsClient::DownloadFile(const std::string& path, const Headers& header, const std::wstring& output_path)
	{
		return false;
	}

	void HttpsClient::Disconnect()
	{
		if (_security && _is_handshake)
		{
			_security->shutdown();
			_is_handshake = false;
		}
		if (_transport && _is_connected)
		{
			_transport->disconnect();
			_is_connected = false;
		}
	}
}	// NetworkOperations
