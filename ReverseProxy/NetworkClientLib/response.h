#pragma once
#include <map>
#include <string>
#include "multiparts.h"

class Response 
{
public:
    Response();
    Response(const std::string& data, bool only_header = false);
    Response(const char* data, int size, bool only_header = false);
    int getStatus() const;
    std::string getStatusPhrase() const;
    std::string getProtocol() const;
    std::string getHeader() const;
    std::map<std::string, std::string> getHeaders() const;
    std::map<std::string, std::string> getCookies() const;
    std::string getBody() const;
    void setBody(const std::string& data);
    std::size_t getBodyLength() const;
    void setBodyLength(const std::size_t& length);
    std::string get_string() const;
    std::size_t get_size() const;
    bool is_empty() const;
    bool is_multipart_form_data() const;
    int num_header() const;
    void clear();
private:
    bool parse_response(const char* data, int size);
    bool parse_header_only(const char* data, int size);
private:
    int _status = 0;
    std::string _status_phrase;
    std::string _protocol;
    std::string _version;
    std::map<std::string, std::string> _headers;
    std::map<std::string, std::string> _cookies;
    std::string _body;
    std::size_t _body_length = 0;
    bool _body_length_provided = false;
    std::size_t _body_index = 0;
    std::string _cache;
};