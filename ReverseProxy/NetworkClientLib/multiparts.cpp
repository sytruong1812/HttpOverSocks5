#include "multiparts.h"

namespace NetworkOperations 
{
    static std::string trim(const std::string& s)
    {
        size_t start = s.find_first_not_of(" \t\r\n");
        if (start == std::string::npos) return "";
        size_t end = s.find_last_not_of(" \t\r\n");
        return s.substr(start, end - start + 1);
    }

    void MultipartParser::parseFormData(const char* data, size_t len)
    {
        std::string full_boundary = "--" + _boundary;
        std::string end_boundary = full_boundary + "--";
        size_t pos = 0;

        while (pos < len)
        {
            size_t boundary_pos = -1;
            for (size_t i = pos; i + full_boundary.size() <= len; ++i)
            {
                if (strncmp(data + i, full_boundary.c_str(), full_boundary.size()) == 0)
                {
                    boundary_pos = i;
                    break;
                }
            }
            if (boundary_pos == -1) break;

            pos = boundary_pos + full_boundary.size();

            if (pos + 2 <= len && data[pos] == '-' && data[pos + 1] == '-')
                break;

            if (!(pos + 2 <= len && data[pos] == '\r' && data[pos + 1] == '\n'))
                break;
            pos += 2;

            Part part;
            while (true)
            {
                if (pos + 2 > len) break;

                if (data[pos] == '\r' && data[pos + 1] == '\n')
                {
                    pos += 2;
                    break;
                }

                size_t line_end = -1;
                for (size_t i = pos; i + 1 < len; ++i)
                {
                    if (data[i] == '\r' && data[i + 1] == '\n')
                    {
                        line_end = i;
                        break;
                    }
                }
                if (line_end == -1) break;

                std::string header_line(data + pos, line_end - pos);
                pos = line_end + 2;

                size_t colon_pos = header_line.find(':');
                if (colon_pos != std::string::npos)
                {
                    std::string header_name = trim(header_line.substr(0, colon_pos));
                    std::string header_value = trim(header_line.substr(colon_pos + 1));
                    part.headers[header_name] = header_value;
                    if (header_name == "Content-Disposition")
                    {
                        part.field_params = parseContentDispositionParams(header_value);
                    }
                }
            }

            size_t next_boundary_pos = -1;
            for (size_t i = pos; i +full_boundary.size() + 2 <= len; ++i)
            {
                if (data[i] == '\r' && data[i + 1] == '\n' &&
                    strncmp(data + i + 2, full_boundary.c_str(), full_boundary.size()) == 0)
                {
                    next_boundary_pos = i;
                    break;
                }
            }
            if (next_boundary_pos == -1)
                next_boundary_pos = len;

            size_t body_len = next_boundary_pos - pos;
            if (body_len > 0)
            {
                part.content_data = std::string(data + pos, body_len);
                if (part.content_data.size() >= 2 && part.content_data.substr(part.content_data.size() - 2) == "\r\n")
                    part.content_data.erase(part.content_data.size() - 2);
            }

            pos = next_boundary_pos;
            _parts.push_back(part);
        }
    }

    NameValues MultipartParser::parseContentDispositionParams(const std::string& data)
    {
        NameValues params;
        size_t pos = 0;
        size_t len = data.length();

        while (pos < len)
        {
            size_t sep = data.find_first_of(';', pos);
            std::string token = data.substr(pos, sep - pos);
            token = trim(token);

            size_t eqPos = token.find('=');
            if (eqPos != std::string::npos)
            {
                std::string key = trim(token.substr(0, eqPos));
                std::string val = trim(token.substr(eqPos + 1));
                if (!val.empty() && val.front() == '"' && val.back() == '"')
                    val = val.substr(1, val.size() - 2);
                params[key] = val;
            }
            else
            {
                params["type"] = token;
            }

            if (sep == std::string::npos) break;
            pos = sep + 1;
        }
        return params;
    }

    std::string MultipartParser::getContentByFilename(const std::string& filename)
    {
        for (const auto& part : _parts)
        {
            if (part.field_params.find("filename") != part.field_params.end())
            {
                return part.content_data;
            }
        }
        return "";
    }

    std::ostream& MultipartWriter::write_data()
    {
        if (_writer == NULL)
        {
            return std::cout;
        }
        return *_writer;
    }

    void MultipartWriter::write_string(const char* str)
    {
        write_data() << "\"";
        for (int i = 0; str[i] != 0; i++)
        {
            char c = str[i];
            switch (c)
            {
                case '"': write_data() << "\\\""; break;
                case '\\': write_data() << "\\\\"; break;
                case '\b': write_data() << "\\b"; break;
                case '\f': write_data() << "\\f"; break;
                case '\n': write_data() << "\\n"; break;
                case '\r': write_data() << "\\r"; break;
                case '\t': write_data() << "\\t"; break;
                default: write_data() << c; break;
            }
        }
        write_data() << "\"";
    }

    std::string MultipartWriter::GetMimeTypeFromExtension(const std::string& ext)
    {
        std::string lowerExt = ext;
        std::transform(lowerExt.begin(), lowerExt.end(), lowerExt.begin(), ::tolower);

        if (lowerExt == ".txt")  return "text/plain";
        if (lowerExt == ".json") return "application/json";
        if (lowerExt == ".jpg" || lowerExt == ".jpeg") return "image/jpeg";
        if (lowerExt == ".png")  return "image/png";
        if (lowerExt == ".gif")  return "image/gif";
        if (lowerExt == ".pdf")  return "application/pdf";
        if (lowerExt == ".csv")  return "text/csv";
        if (lowerExt == ".zip")  return "application/zip";
        if (lowerExt == ".xml")  return "application/xml";
        return "application/octet-stream";
    }

    std::ostream* MultipartWriter::GetWriter()
    {
        return _writer;
    }
    void MultipartWriter::SetWriter(std::ostream* writer)
    {
        this->_writer = writer;
    }
    void MultipartWriter::Start(const std::string& boundary)
    {
        _boundary = boundary;
    }
    void MultipartWriter::AddField(const std::string& name, const std::string& value)
    {
        write_data() << "--" << _boundary << "\r\n";
        write_data() << "Content-Disposition: form-data; " << "name=" << "\"" << name << "\"";
        write_data() << "\r\n\r\n";
        write_data() << value << "\r\n";
    }
    void MultipartWriter::AddField(const std::string& name, const Headers& headers, const std::string& value)
    {
        write_data() << "--" << _boundary << "\r\n";
        write_data() << "Content-Disposition: form-data; " << "name=" << "\"" << name << "\"";
        write_data() << "\r\n";
        for (const auto& it : headers)
        {
            write_data() << it.first << ": " << it.second << "\r\n";
        }
        write_data() << "\r\n";
        write_data() << value << "\r\n";
    }
    void MultipartWriter::AddField(const std::string& name, const std::pair<std::string, std::string>& header, const std::string& value)
    {
        write_data() << "--" << _boundary << "\r\n";
        write_data() << "Content-Disposition: form-data; " << "name=" << "\"" << name << "\"";
        write_data() << "\r\n";
        write_data() << header.first << ": " << header.second << "\r\n";     
        write_data() << "\r\n";
        write_data() << value << "\r\n";
    }
    void MultipartWriter::AddFile(const std::string& name, const std::string& file_name, const std::string& file_data)
    {
        write_data() << "--" << _boundary << "\r\n";
        write_data() << "Content-Disposition: form-data; " << "name=" << "\"" << name << "\"; " << "filename=\"" << file_name << "\"";
        write_data() << "\r\n";
        size_t dot = file_name.find_last_of('.');
        if (dot != std::string::npos)
        {
            std::string ext = file_name.substr(dot);
            std::string mine = GetMimeTypeFromExtension(ext);
            write_data() << "Content-Type: " << mine << "\r\n";
        }
        else
        {
            write_data() << "Content-Type: application/octet-stream" << "\r\n";
        }
        write_data() << "\r\n";
        write_data() << file_data << "\r\n";

    }
    void MultipartWriter::AddFile(const std::string& name, const std::string& file_name, const unsigned char* file_data, size_t file_size)
    {
        write_data() << "--" << _boundary << "\r\n";
        write_data() << "Content-Disposition: form-data; " << "name=" << "\"" << name << "\"; " << "filename=\"" << file_name << "\"";
        write_data() << "\r\n";
        size_t dot = file_name.find_last_of('.');
        if (dot != std::string::npos)
        {
            std::string ext = file_name.substr(dot);
            std::string mine = GetMimeTypeFromExtension(ext);
            write_data() << "Content-Type: " << mine << "\r\n";
        }
        else
        {
            write_data() << "Content-Type: application/octet-stream" << "\r\n";
        }
        write_data() << "\r\n";
        write_data() << std::string(reinterpret_cast<const char*>(file_data), file_size) << "\r\n";
    }
    void MultipartWriter::AddFile(const std::string& name, const std::string& file_name, const std::wstring& file_path)
    {
        write_data() << "--" << _boundary << "\r\n";
        write_data() << "Content-Disposition: form-data; " << "name=" << "\"" << name << "\"; " << "filename=\"" << file_name << "\"";
        write_data() << "\r\n";
        size_t dot = file_name.find_last_of('.');
        if (dot != std::string::npos)
        {
            std::string ext = file_name.substr(dot);
            std::string mine = GetMimeTypeFromExtension(ext);
            write_data() << "Content-Type: " << mine << "\r\n";
        }
        else
        {
            write_data() << "Content-Type: application/octet-stream" << "\r\n";
        }
        write_data() << "\r\n";
        DWORD szData = 0;
        BYTE* pData = nullptr;
        if (Helper::FileHelper::ReadFileData(file_path, pData, szData) && pData)
        {
            if (pData && szData > 0)
            {
                write_data() << std::string((const char*)pData, szData) << "\r\n";
                delete[] pData;
            }            
        }
    }
    void MultipartWriter::Finish()
    {
        write_data() << "--" << _boundary << "--";
    }

}