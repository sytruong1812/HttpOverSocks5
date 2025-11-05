#include <iostream>
#include "http.h"
#include "https.h"
#include "utils.h"
#include "json_parser.h"
#include "json_writer.h"

#define SERVER_DEST_HOST    "127.0.0.2"
#define SERVER_HTTP_PORT    8080
#define SERVER_HTTPS_PORT   8443

#define SERVER_PROXY_HOST   "127.0.0.10"
#define SERVER_PROXY_PORT   4444
#define PROXY_USERNAME      "admin"
#define PROXY_PASSWORD      "qwerty"

#ifdef ENABLE_MBEDTLS
#define SERVER_CERT_PATH "E:\\Resource\\Certificate\\server\\cert_server.pem"
#define SERVER_PRIVATE_KEY_PATH "E:\\Resource\\Certificate\\server\\key_server.pem"
#define SERVER_PRIVATE_KEY_PASSWORD "qwerty"

#define CLIENT_CERT_PATH "E:\\Resource\\Certificate\\client\\cert_client.pem"
#define CLIENT_PRIVATE_KEY_PATH "E:\\Resource\\Certificate\\client\\key_client.pem"
#define CLIENT_PRIVATE_KEY_PASSWORD "qwerty"
#else  /* ENABLE_SCHANNEL */
#define SERVER_CERT_PATH "E:\\Resource\\Certificate\\server.pfx"
#define SERVER_CERT_PASSWORD "qwerty"
#define SERVER_SUBJECT_NAME "localhost"

#define CLIENT_CERT_PATH "E:\\Resource\\Certificate\\client.pfx"
#define CLIENT_CERT_PASSWORD "qwerty"
#define CLIENT_SUBJECT_NAME "localhost"
#endif /* ENABLE_MBEDTLS */

using namespace NetworkOperations;

void TEST_SOCKS5_TCP()
{
    //step1: Create SOCKS5 client with authentication
    auto socks5 = std::make_unique<Socks5Client>(SERVER_PROXY_HOST, SERVER_PROXY_PORT, SOCKET_TYPES::TCP_STREAM);

    //step2: Connect via proxy: Client --> SOCKS5 Proxy (127.0.0.10:4444) --> http://localhost:8080
    int result = socks5->connect(SERVER_DEST_HOST, SERVER_HTTP_PORT);
    if (result != SOCKS5_OK)
    {
        return;
    }
    //step3: Build POST request to send
    std::string json_request = "{\r\n  \"user_name\": \"teddy\",\r\n  \"password\": \"qwerty\"\r\n}";
    auto request = std::make_unique<Request>("POST", "/login", "HTTP/1.1");
    {
        request->setHeader("User-Agent", "Cloud Storage Client");
        request->setHeader("Content-Type", "application/json");
        request->setBody(json_request);
    }
    //step4: Send data to server
    if (socks5->tcp_send_data(request->get_string().c_str(), (int)request->get_size()) <= 0)
    {
        return;
    }
    //step5: Receive data from server
    int buf_size = 1024;
    char* buffer = new char[buf_size];
    if (socks5->tcp_recv_data(buffer, buf_size) <= 0)
    {
        delete[] buffer;
        return;
    }
    else
    {
        std::cout << buffer << std::endl;
    }
    delete[] buffer;
}

void TEST_SOCKS5_UDP()
{
    int result = SOCKS5_OK;
    auto socks5 = std::make_unique<Socks5Client>(SERVER_PROXY_HOST, SERVER_PROXY_PORT, SOCKET_TYPES::UDP_DATAGRAM);

    //step 1: Open a TCP connection to the SOCKS5 server;
    //step 2: Send a UDP ASSOCIATE request (cf section 4);
    //step 3: Receive from the Server the address and port where it must send UDP packets to be relayed;       
    result = socks5->connect("127.0.0.8", 8000);
    if (result != SOCKS5_OK)
    {
        return;
    }
    //step 4: Send datagrams (UDP) to that address, encapsulated with some headers (cf section 7).
    int dest_port = SERVER_PROXY_PORT;
    const char* dest_addr = SERVER_PROXY_HOST;
    std::string send_data = "Hello World!";
    result = socks5->udp_send_to(dest_addr, dest_port, send_data.c_str(), (int)send_data.size());
    if (result <= 0)
    {
        return;
    }
    std::cout << "UDP send to: " << dest_addr << ":" << dest_port << std::endl;
    std::cout << "UDP send data: " << send_data << std::endl;

    //step 5: Receive from the server, parse get data from datagrams (UDP)
    int sender_port = 0;
    char* sender_addr = nullptr;
    auto receive_data = std::make_unique<char[]>(6 * 1024);
    result = socks5->udp_recv_from(&sender_addr, &sender_port, receive_data.get(), 6 * 1024);
    if (result <= 0)
    {
        return;
    }
    std::cout << "UDP receive from: " << sender_addr << ":" << sender_port << std::endl;
    std::cout << "UDP receive data: " << receive_data.get() << std::endl;
}

void TEST_HTTP()
{
    auto http = std::make_unique<HttpClient>();
    if (!http->ConnectViaSocks5("github.com", SERVER_HTTP_PORT, SERVER_PROXY_HOST, SERVER_PROXY_PORT))
    {
        return;
    }
    Headers header;
    std::wstring path = L"C:\\Users\\sytru\\Downloads\\README.txt";
    if (http->DownloadFile("/sytruong1812/Embedded-in-Automotive/blob/main/README.md", header, path))
    {
        std::cout << "Download file done!" << std::endl;
    }
    http->Disconnect();
}

#ifdef ENABLE_MBEDTLS
void TEST_HTTPS_MbedTLS()
{
    auto https = std::make_unique<HttpsClient>(SERVER_CERT_PATH);
    if (!https->Connect(SERVER_DEST_HOST, SERVER_HTTPS_PORT))
    {
        return;
    }
    // GET API
    Headers header1 =
    {
        {"User-Agent", "Cloud Storage Client"},
    };
    auto response1 = https->Get("/", header1);
    if (response1)
    {
        std::cout << response1->get_string() << std::endl;
    }
    // POST API
    Headers header2 =
    {
        {"User-Agent", "Cloud Storage Client"},
    };
    auto response2 = https->Post("/", header2, "");
    if (response2)
    {
        std::cout << response2->get_string() << std::endl;
    }
    https->Disconnect();
}
#else  /* ENABLE_SCHANNEL */
void TEST_HTTPS_SCHANNEL()
{
    auto https = std::make_unique<HttpsClient>();
    if (!https->ConnectViaSocks5(SERVER_DEST_HOST, SERVER_HTTPS_PORT, SERVER_PROXY_HOST, SERVER_PROXY_PORT))
    {
        return;
    }
    // GET API
    Headers header1 =
    {
        {"User-Agent", "Cloud Storage Client"},
        {"Connection", "close"},
    };
    auto response1 = https->Get("/Hello.txt", header1);
    if (response1)
    {
        std::cout << response1->get_string() << std::endl;
    }
    // POST API
    Headers header2 =
    {
        {"User-Agent", "Cloud Storage Client"},
        {"Connection", "close"},
    };
    auto response2 = https->Post("/Hello.txt", header2, "Hello World!");
    if (response2)
    {
        std::cout << response2->get_string() << std::endl;
    }
    https->Disconnect();
}
#endif /* ENABLE_MBEDTLS */

void TEST_MultiParts()
{
    std::ostringstream os;
    auto writer = std::make_unique<MultipartWriter>(&os);
    writer->Start("7MA4YWxkTrZu0gW");
    writer->AddField("username", "teddy");
    Headers header;
    {
        header.insert(std::make_pair("Content-Type", "application/json"));
    }
    writer->AddField("metadata", header, "{\"foo\":\"bar\"}");
    writer->AddFile("profile_picture", "profile.jpg", "01010101010101010101");
    writer->AddFile("file_data", "file.txt", L"E:\\DEV\\Resource\\Folder\\folder\\file.txt");
    writer->Finish();
    std::string request_body = os.str();

    auto parser = std::make_unique<MultipartParser>("7MA4YWxkTrZu0gW", request_body.c_str(), (int)request_body.length());
    auto parts = parser->getPartsCollection();
    auto profile_picture = parser->getContentByFilename("profile.jpg");
    auto file_data = parser->getContentByFilename("file.txt");
}

void TEST_UploadFile(std::wstring input_path)
{
    auto https = std::make_unique<HttpsClient>();
    if (!https->Connect(SERVER_DEST_HOST, SERVER_HTTPS_PORT))
    {
        return;
    }
    std::ostringstream metadata;
    {
        auto jw = std::make_unique<JsonWriter>();
        jw->SetWriter(&metadata);
        jw->StartObject();
        jw->KeyValue("file_name", "Hello.txt");
        jw->KeyValue("file_size", 12);
        jw->KeyValue("attribute", 32);
        jw->KeyValue("create_time", "2025-06-18 04:36:51");
        jw->KeyValue("last_write_time", "2025-06-13 04:28:22");
        jw->KeyValue("last_access_time", "2025-06-22 03:36:47");
        jw->EndObject();
    }
    Headers header =
    {
        {"User-Agent", "Cloud Storage Client"},
        {"Content-Type", "multipart/form-data;boundary=\"89B2D3F8-C287-4592-A82E-79E71EF6DF5C\""}
    };
    std::ostringstream body;
    {
        auto writer = std::make_unique<MultipartWriter>(&body);
        writer->Start("89B2D3F8-C287-4592-A82E-79E71EF6DF5C");
        writer->AddField("metadata", std::make_pair("Content-Type", "application/json"), metadata.str());
        writer->AddFile("filedata", "Hello.txt", input_path);
        writer->Finish();
    }
    auto response = https->Post("/Hello.txt", header, body.str());
    if (!response || response->getStatus() != 200)
    {
        return;
    }
    std::cout << "-----------[ Upload File ]-----------" << std::endl;
    std::cout << "Status Code: " << response->getStatus() << std::endl;
    std::cout << response->getHeader() << std::endl;
    std::cout << response->getBody() << std::endl;
}

void TEST_DownloadFile(std::wstring output_path)
{
    auto https = std::make_unique<HttpsClient>();
    if (!https->Connect(SERVER_DEST_HOST, SERVER_HTTPS_PORT))
    {
        return;
    }
    Headers header =
    {
        {"User-Agent", "Cloud Storage Client"},
        {"Content-Type", "application/octet-stream"}
    };
    auto response = https->Get("/500MB.txt", header);
    if (!response || response->getStatus() != 200)
    {
        return;
    }
    std::string file_data = response->getBody();
    if (!Helper::FileHelper::WriteFileData(output_path, (BYTE*)file_data.c_str(), (DWORD)file_data.size()))
    {
        return;
    }
    std::cout << "-----------[ Download File ]-----------" << std::endl;
    std::cout << "Status Code: " << response->getStatus() << std::endl;
    std::cout << response->getHeader() << std::endl;
}

int main(int argc, char* argv[])
{
    ENABLE_LOG(TRUE);
    SET_LOG_OUT(SHOW_MESSAGE);
    SET_LOG_LEVEL(LOG_CRITICAL);

    wsocket_global_startup();

    //TEST_SOCKS5_TCP();
    //TEST_SOCKS5_UDP();
    TEST_HTTP();
#ifdef ENABLE_MBEDTLS
    //TEST_HTTPS_MbedTLS();
#else  /* ENABLE_SCHANNEL */
    //TEST_HTTPS_SCHANNEL();
#endif /* ENABLE_MBEDTLS */
    //TEST_MultiParts();
    //TEST_UploadFile(L"C:\\Users\\Admin\\Downloads\\Hello.txt");
    //TEST_DownloadFile(L"C:\\Users\\Admin\\Downloads\\500MB.txt");

    wsocket_global_cleanup();

    return 0;
}