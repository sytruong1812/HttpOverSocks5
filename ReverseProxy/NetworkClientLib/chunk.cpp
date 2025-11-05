#include <locale>
#include <string>
#include <algorithm>
#include <functional>
#include "chunk.h"

std::string ChunkTransfer::read_line(void* socket, bool incl_endl) 
{
	char c = '\0';
	char c_last = '\0';
	std::string line;
	while (::recv((SOCKET)socket, &c, 1, 0) > 0)
	{
		if (c_last == '\r') 
		{
			if (c == '\n') 
			{
				if (incl_endl) 
				{
					line += c;
				}
				else 
				{
					line.erase(line.size() - 1);
				}
				break;
			}
		}
		line += c;
		c_last = c;
	}
	return line;
}

std::string ChunkTransfer::read_data(void* socket, size_t size)
{
	std::string data = "";
	char buffer[CHUNK_SIZE_DEFAULT];
	// Loop until we have read all the bytes
	while (size > 0) 
	{
		// Read from socket
		int bytes_received = ::recv((SOCKET)socket, buffer, (int)(min(size, CHUNK_SIZE_DEFAULT)), 0);
		if (bytes_received == SOCKET_ERROR)
		{
			break;
		}
		// Append to data
		data.append(buffer, bytes_received);
		// Update size with remaining bytes
		size -= bytes_received;
	}
	return data;
}

uint32_t ChunkTransfer::read_chunk_size(void* socket) 
{
	std::vector<std::string> chunk_header;
	std::string line = read_line(socket);
	chunk_header = split(line, ";");
	return hextodec(chunk_header.at(0));
}

std::string ChunkTransfer::read_chunked(void* socket)
{
	uint32_t offset = 0;
	uint32_t chunk_size = 0;
	std::string chunked_data = "";
	while ((chunk_size = read_chunk_size(socket)) > 0)
	{
		offset = (uint32_t)chunked_data.size();
		// Read chunk-data
		chunked_data.append(read_data(socket, chunk_size));
		// Sanity check
		if ((chunked_data.size() - offset) != chunk_size)
		{
			// Something went wrong
			break;
		}
		// Extra \r\n
		read_data(socket, 2);
	}
	// Read until the end of chunked data
	while (read_line(socket, true).size() > 2);

	return chunked_data;
}

void ChunkTransfer::read_chunk_header(void* socket, chunk_t& chunk)
{
	std::vector<std::string> chunk_header;
	std::string line = read_line(socket);
	chunk_header = split(line, ";");
	// Sanity check
	if (chunk_header.size() > 0)
	{
		// Sanity check
		if (chunk_header.at(0).size() > 0) 
		{
			chunk.size = hextodec(chunk_header.at(0));
		}
		// Check for chunk-extension
		if (chunk_header.size() == 2) 
		{
			chunk.extention = trim(chunk_header.at(1));
		}
	}
}

chunk_t ChunkTransfer::read_chunk(void* socket)
{
	chunk_t chunk;
	std::string line;
	std::vector<std::string> chunk_header;

	// Initialise chunk
	chunk.size = 0;
	chunk.extention = "";
	chunk.data = "";

	// Read chunk header
	read_chunk_header(socket, chunk);

	// Read chunk data
	if (chunk.size > 0)
	{
		chunk.data = read_data(socket, chunk.size);
	}
	// Read \r\n ending for the chunk
	read_data(socket, 2);

	return chunk;
}

bool ChunkTransfer::read_chunked_payload(void* socket, std::string& payload)
{
	chunk_t chunk;
	bool ieof = false;
	do 
	{
		// Read chunk
		chunk = read_chunk(socket);
		// Append to payload
		payload.append(chunk.data);
		// Sanity check
		if (chunk.data.size() != chunk.size) 
		{
			// Something went wrong
			break;
		}
	} while (chunk.size > 0);
	// Check for ieof
	if (chunk.extention == "ieof") 
	{
		ieof = true;
	}
	return ieof;
}

bool ChunkTransfer::send_line(void* socket, const std::string& data)
{
	std::string line = data + "\r\n";
	int bytes_sented = ::send((SOCKET)socket, line.c_str(), (int)line.size(), 0);
	if (bytes_sented == SOCKET_ERROR)
	{
		return false;
	}
	return true;
}

bool ChunkTransfer::send_data(void* socket, const std::string& data)
{
	int bytes_sented = ::send((SOCKET)socket, data.c_str(), (int)data.size(), 0);
	if (bytes_sented == SOCKET_ERROR)
	{
		return false;
	}
	return true;
}

bool ChunkTransfer::send_chunked(void* socket, const std::string& data)
{
	size_t offset = 0;
	size_t number_of_chunks = 0;
	std::string chunked_data = "";

	// Calculate the number of chunks we need
	if (data.size() > CHUNK_SIZE_DEFAULT) 
	{
		number_of_chunks = (data.size() / CHUNK_SIZE_DEFAULT);
	}
	do 
	{
		// Prepare data for this chunk
		chunked_data = data.substr(offset, CHUNK_SIZE_DEFAULT);
		// Sanity check
		if (chunked_data.size() <= 0) 
		{
			// We shouldn't get here
			break;
		}
		// Update offset
		offset += chunked_data.size();
		//  Send chunk-size + CRLF
		if (!send_line(socket, dectohex((uint32_t)chunked_data.size())))
		{
			return false;
		}
		// Send chunk-data + CRLF
		if (!send_data(socket, chunked_data)) 
		{
			return false;
		}
		number_of_chunks--;

	} while (number_of_chunks > 0);

	// End of chunk
	if (!send_data(socket, "\r\n0\r\n\r\n"))
	{
		return false;
	}
	return true;
}

uint32_t ChunkTransfer::hextodec(const std::string& hex)
{
	uint32_t dec;
	std::stringstream ss;
	ss << std::hex << hex;
	ss >> dec;
	return dec;
}

std::string ChunkTransfer::dectohex(const uint32_t& dec)
{
	std::string hex;
	std::stringstream ss;
	ss << std::hex << dec;
	ss >> hex;
	return hex;
}

std::string& ChunkTransfer::trim(std::string& str)
{
	return ltrim(rtrim(str));
}

std::string& ChunkTransfer::rtrim(std::string& str)
{
	str.erase(std::find_if(str.rbegin(), str.rend(), std::not1(std::ptr_fun<int, int>(std::isspace))).base(), str.end());
	return str;
}

std::string& ChunkTransfer::ltrim(std::string& str)
{
	str.erase(str.begin(), std::find_if(str.begin(), str.end(), std::not1(std::ptr_fun<int, int>(std::isspace))));
	return str;
}

std::vector<std::string> ChunkTransfer::split(const std::string& str, const std::string& delimiter)
{
	size_t current;
	size_t next = -1;
	std::vector<std::string> result;
	do {
		current = next + 1;
		next = str.find_first_of(delimiter, current);
		result.push_back(str.substr(current, (next - current)));
	} while (next != std::string::npos);
	return result;
}

