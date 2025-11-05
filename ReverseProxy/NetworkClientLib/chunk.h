#pragma once
#include <string>
#include <vector>
#include <sstream>
#include "socket.h"

#define CHUNK_SIZE_DEFAULT 1024

/*
 * Chunk format (simplified):
 *
 * <HEX SIZE>[ chunk extension ] CRLF
 * <DATA> CRLF
 *
 * Highlights from RFC2616 section 3.6 say:

   The chunked encoding modifies the body of a message in order to
   transfer it as a series of chunks, each with its own size indicator,
   followed by an OPTIONAL trailer containing entity-header fields. This
   allows dynamically produced content to be transferred along with the
   information necessary for the recipient to verify that it has
   received the full message.

	   Chunked-Body   = *chunk
						last-chunk
						trailer
						CRLF

	   chunk          = chunk-size [ chunk-extension ] CRLF
						chunk-data CRLF
	   chunk-size     = 1*HEX
	   last-chunk     = 1*("0") [ chunk-extension ] CRLF

	   chunk-extension= *( ";" chunk-ext-name [ "=" chunk-ext-val ] )
	   chunk-ext-name = token
	   chunk-ext-val  = token | quoted-string
	   chunk-data     = chunk-size(OCTET)
	   trailer        = *(entity-header CRLF)

   The chunk-size field is a string of hex digits indicating the size of
   the chunk. The chunked encoding is ended by any chunk whose size is
   zero, followed by the trailer, which is terminated by an empty line.

 */

struct chunk_t 
{
	uint32_t size;
	std::string data;
	std::string extention;
};

class ChunkTransfer 
{
public:
	static std::string read_line(void* socket, bool incl_endl = false);
	static std::string read_data(void* socket, size_t size);

	static uint32_t read_chunk_size(void* socket);
	static std::string read_chunked(void* socket);

	static chunk_t read_chunk(void* socket);
	static void read_chunk_header(void* socket, chunk_t& chunk);
	static bool read_chunked_payload(void* socket, std::string& payload);

	static bool send_line(void* socket, const std::string& data);
	static bool send_data(void* socket, const std::string& data);
	static bool send_chunked(void* socket, const std::string& data);
private:
	static uint32_t hextodec(const std::string& hex);
	static std::string dectohex(const uint32_t& dec);
	static std::string& trim(std::string& str);
	static std::string& rtrim(std::string& str);
	static std::string& ltrim(std::string& str);
	static std::vector<std::string> split(const std::string& str, const std::string& delimiter = " ");
};


