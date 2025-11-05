#include "request.h"

Request::Request()
{
    clear();
}

Request::Request(const std::string& method, const std::string& url, const std::string& protocol)
{
    // Clear the HTTP request cache
    clear();
    // Append the HTTP request method
    _cache << method;
    _method = method;
    _cache << " ";
    // Append the HTTP request URL
    _cache << url;
    _url = url;
    _cache << " ";
    // Append the HTTP request protocol version
    _cache << protocol;
    _protocol = protocol;
    _cache << "\r\n";
}

/*=====================[ HEADER ]=======================*/
void Request::setHeader(const std::string& key, const std::string& value)
{
    // Append the HTTP request header's key
    _cache << key;
    _cache << ": ";
    // Append the HTTP request header's value
    _cache << value;
    _cache << "\r\n";
    // Add the header to the corresponding collection
    _headers[key] = value;

}
bool Request::hasHeader(const std::string& key)
{
    return _headers.find(key) != _headers.end() ? true : false;
}
/*=====================[ COOKIE ]=======================*/
void Request::setCookie(const std::string& name, const std::string& value)
{
    std::string key = "Cookie";
    std::string cookie = name + "=" + value;
    // Append the HTTP request header's key
    _cache << key;
    _cache << ": ";
    // Append Cookie
    _cache << cookie;
    _cache << "\r\n";
    // Add the header to the corresponding collection
    _headers[key] = cookie;
    // Add the cookie to the corresponding collection
    _cookies[name] = value;
}
void Request::addCookie(const std::string& name, const std::string& value)
{
    // Append Cookie
    _cache << "; ";
    _cache << name;
    _cache << "=";
    _cache << value;
    // Add the cookie to the corresponding collection
    _cookies[name] = value;
}
/*======================[ BODY ]========================*/
void Request::setBodyLength(int length)
{
    // Append content length header
    _body_length = (int)length;
    setHeader("Content-Length", std::to_string(_body_length));
    _cache << "\r\n";
}
void Request::setBody(const std::string& body)
{
    // Append content length header
    _body_length = body.length();
    if (_headers.find("Transfer-Encoding") == _headers.end() || _headers["Transfer-Encoding"] != "chunked")
    {
        setBodyLength((int)body.length());
    }
    // Append the HTTP request body
    _cache << body;
    _body = body;
}
void Request::setBody(const char* body, int length)
{
    // Append content length header
    _body_length = length;
    if (_headers.find("Transfer-Encoding") == _headers.end() || _headers["Transfer-Encoding"] != "chunked")
    {
        setBodyLength(length);
    }
    // Append the HTTP request body
    _cache << body;
    _body = std::string(body, length);
}
std::string Request::getMethod() const 
{ 
    return _method; 
}
std::string Request::getUrl() const 
{ 
    return _url; 
}
std::string Request::getProtocol() const 
{ 
    return _protocol; 
}
std::string Request::getBody() const 
{ 
    return _body; 
}
std::size_t Request::getBodyLength() const 
{ 
    return _body_length; 
}

std::string Request::getHeaderString() const
{
    std::stringstream stream;
    stream << _method << " " << _url << " " << _protocol << "\r\n";
    for (const auto& pair : _headers)
    {
        stream << pair.first << ": " << pair.second << "\r\n";
    }
    return stream.str();
}
std::string Request::getHeaderValue(const std::string& header)
{
    if (_headers.find(header) != _headers.end())
    {
        return _headers[header];
    }
    return "";
}
std::map<std::string, std::string> Request::getHeaders() const
{
    return _headers;
}
std::map<std::string, std::string> Request::getCookies() const
{
    return _cookies;
}
std::string Request::get_string() const
{
    if (_cache.eof())
    {
        return "";
    }
    return _cache.str();
}
std::size_t Request::get_size() const
{
    return _cache.str().length();
}
bool Request::is_empty()
{
    return _cache.eof();
}
int Request::num_header()
{
    return (int)_headers.size();
}
int Request::num_cookies()
{
    return (int)_cookies.size();
}
void Request::clear()
{
    _method.clear();
    _url.clear();
    _protocol.clear();
    _headers.clear();
    _cookies.clear();
    _body.clear();
    _body_length = 0;
    _is_multipart = false;
    _cache.clear();
}