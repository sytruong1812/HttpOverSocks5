#pragma once
#include <sstream>
#include "utils.h"

namespace NetworkOperations 
{
    typedef std::map<std::string, std::string> Headers;
    typedef std::map<std::string, std::string> NameValues;

    struct Part 
    {
        Headers headers;
        NameValues field_params;
        std::string content_data;
    };

    class MultipartParser 
    {
    private:
        std::string _boundary;
        std::vector<Part> _parts;
        void parseFormData(const char* data, size_t len);
        NameValues parseContentDispositionParams(const std::string& data);
    public:
        MultipartParser(const std::string& boundary, const char* data, size_t len)
            : _boundary(boundary)
        {
            parseFormData(data, len);
        }
        ~MultipartParser() = default;
        std::vector<Part> getPartsCollection() { return _parts; }
        std::string getContentByFilename(const std::string& filename);
    };

    class MultipartWriter 
    {
    private:
        std::string _boundary;
        std::ostream* _writer;
        std::ostream& write_data();
        void write_string(const char* str);
        std::string GetMimeTypeFromExtension(const std::string& ext);
    public:
        MultipartWriter(std::ostream* writer) : _writer(writer) {}
        std::ostream* GetWriter();
        void SetWriter(std::ostream* writer);
        void Start(const std::string& boundary);
        void AddField(const std::string& name, const std::string& value);
        void AddField(const std::string& name, const Headers& headers, const std::string& value);
        void AddField(const std::string& name, const std::pair<std::string, std::string>& header, const std::string& value);
        void AddFile(const std::string& name, const std::string& file_name, const std::string& file_data);
        void AddFile(const std::string& name, const std::string& file_name, const unsigned char* file_data, size_t file_size);
        void AddFile(const std::string& name, const std::string& file_name, const std::wstring& file_path);
        void Finish();
    };
}