#pragma once
#include <map>
#include <string>
#include "multiparts.h"

class Request 
{
public:
    Request();
    Request(const std::string& method, const std::string& url, const std::string& protocol = "HTTP/1.1");
    // Copy constructor
    Request(Request& other) {
        clear();
        _method = other._method;
        _url = other._url;
        _protocol = other._protocol;
        _headers = other._headers;
        _cookies = other._cookies;
        _body = other._body;
        _body_length = other._body_length;
        _is_multipart = other._is_multipart;
        _cache.str(other._cache.str());
    }
    // Assignment operator
    Request& operator=(const Request& other) {
        if (this != &other)
        {
            clear();
            _method = other._method;
            _url = other._url;
            _protocol = other._protocol;
            _headers = other._headers;
            _cookies = other._cookies;
            _body = other._body;
            _body_length = other._body_length;
            _is_multipart = other._is_multipart;
            _cache.str(other._cache.str());
        }
    }
    /*=====================[ HEADER ]=======================*/
    void setHeader(const std::string& key, const std::string& value);
    bool hasHeader(const std::string& key);
    /*=====================[ COOKIE ]=======================*/
    void setCookie(const std::string& name, const std::string& value);
    void addCookie(const std::string& name, const std::string& value);
    /*======================[ BODY ]========================*/
    void setBodyLength(int length);
    void setBody(const std::string& body);
    void setBody(const char* body, int length);
    std::string getMethod() const;
    std::string getUrl() const;
    std::string getProtocol() const;
    std::string getBody() const;
    std::size_t getBodyLength() const;
    std::string getHeaderString() const;
    std::string getHeaderValue(const std::string& header);
    std::map<std::string, std::string> getHeaders() const;
    std::map<std::string, std::string> getCookies() const;
    std::string get_string() const;
    std::size_t get_size() const;
    bool is_empty();
    int num_header();
    int num_cookies();
    void clear();
private:
    std::string _method;
    std::string _url;
    std::string _protocol;
    std::map<std::string, std::string> _headers;
    std::map<std::string, std::string> _cookies;
    std::string _body;
    std::size_t _body_length = 0;
    bool _is_multipart = false;
    std::stringstream _cache;
};