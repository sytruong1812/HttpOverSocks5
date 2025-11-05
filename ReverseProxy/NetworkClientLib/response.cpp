#include "response.h"

Response::Response() 
{
    clear();
}

Response::Response(const std::string& data, bool only_header)
{
    clear();
    if (only_header)
    {
        parse_header_only(data.c_str(), (int)data.size());
    }
    else
    {
        parse_response(data.c_str(), (int)data.size());
    }
}

Response::Response(const char* data, int size, bool only_header)
{
    clear();
    if (only_header)
    {
        parse_header_only(data, size);
    }
    else
    {
        parse_response(data, size);
    }
}

int Response::getStatus() const 
{ 
    return _status; 
}

std::string Response::getStatusPhrase() const 
{ 
    return _status_phrase; 
}

std::string Response::getProtocol() const 
{ 
    return _protocol; 
}

std::string Response::getHeader() const 
{
    std::stringstream stream;
    for (const auto& pair : _headers)
    {
        stream << pair.first << ": " << pair.second << "\r\n";
    }
    return stream.str();
}

std::map<std::string, std::string> Response::getHeaders() const
{
    return _headers;
}

bool Response::parse_header_only(const char* data, int size)
{
    if (!data)
    {
        return false;
    }
    std::string line;
    std::istringstream stream(std::string(data, size));
    while (std::getline(stream, line))
    {
        size_t colonPos = line.find(":");
        if (colonPos != std::string::npos)
        {
            std::string name = line.substr(0, colonPos);
            std::string value = line.substr(colonPos + 2, line.length() - colonPos - 3); // Also remove \r
            _headers[name] = value;
        }
    }
    return true;
}

std::map<std::string, std::string> Response::getCookies() const
{
    return _cookies;
}

std::string Response::getBody() const 
{ 
    return _body; 
}

void Response::setBody(const std::string& data)
{
    _body = data;
}

std::size_t Response::getBodyLength() const 
{ 
    if (_body_length_provided)
    {
        return _body.length();
    }
    return _body_length; 
}

void Response::setBodyLength(const std::size_t& length)
{
    _body_length = length;
}

std::string Response::get_string() const 
{
    if (_cache.empty())
    {
        return "";
    }
    return _cache;
}

std::size_t Response::get_size() const
{
    return _cache.size();
}

bool Response::is_empty() const
{
    return _cache.empty();
}

bool Response::is_multipart_form_data() const
{
    auto it = _headers.find("Content-Type");
    if (it == _headers.end())
    {
        return false;
    }
    return it->second.find("multipart/form-data") != std::string::npos;
}

int Response::num_header() const
{
    return static_cast<int>(_headers.size());
}

void Response::clear()
{
    _status = 0;
    _status_phrase.clear();
    _protocol.clear();
    _version.clear();
    _headers.clear();
    _cookies.clear();
    _body.clear();
    _body_length = 0;
    _body_length_provided = false;
    _body_index = 0;
    _cache.clear();
}

bool Response::parse_response(const char* data, int size)
{
    _cache.append(data, size);

    // Parse status line
    size_t index = 0;
    size_t line_end = _cache.find("\r\n", index);
    if (line_end == std::string::npos)
    {
        return false;
    }
    std::string status_line = _cache.substr(index, line_end - index);
    index = line_end + 2;

    std::istringstream status_stream(status_line);
    status_stream >> _protocol >> _status;
    std::getline(status_stream, _status_phrase);
    if (!_status_phrase.empty() && _status_phrase[0] == ' ')
    {
        _status_phrase.erase(0, 1);
    }

    // Parse headers
    size_t header_end = _cache.find("\r\n\r\n");
    if (header_end == std::string::npos)
    {
        return false; // incomplete header
    }
    while (index < header_end)
    {
        size_t next_line = _cache.find("\r\n", index);
        if (next_line == std::string::npos)
        {
            return false;
        }
        std::string line = _cache.substr(index, next_line - index);
        index = next_line + 2;

        size_t colonPos = line.find(':');
        if (colonPos == std::string::npos)
        {
            continue;
        }
        std::string name = line.substr(0, colonPos);
        std::string value = line.substr(colonPos + 1);
        value.erase(0, value.find_first_not_of(" \t")); // trim left spaces
        _headers[name] = value;

        if (std::strcmp(name.c_str(), "Content-Length") == 0)
        {
            _body_length = std::stoi(value);
            _body_length_provided = true;
        }
    }
    // Parse body
    _body_index = header_end + 4;
    if (_body_length_provided && _cache.size() >= _body_index + _body_length)
    {
        _body = _cache.substr(_body_index, _body_length);
    }
    else
    {
        _body = _cache.substr(_body_index); // may be incomplete
    }
    return true;
}