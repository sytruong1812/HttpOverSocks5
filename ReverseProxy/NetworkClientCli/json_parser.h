#pragma once
#include <map>
#include <vector>
#include <string>

#define wcsncasecmp _wcsnicmp
static inline bool isnan(double x) { return x != x; }
static inline bool isinf(double x) { return !isnan(x) && isnan(x - x); }

// Custom types
class JsonValue;
typedef std::vector<JsonValue*> JsonArray;
typedef std::map<std::wstring, JsonValue*> JsonObject;

#include "json_value.h"

class JsonParser
{
	friend class JsonValue;
public:
	static JsonValue* Parse(const char* data);
	static JsonValue* Parse(const wchar_t* data);
	static std::wstring Stringify(const JsonValue* value);
protected:
	static bool SkipWhitespace(const wchar_t** data);
	static bool ExtractString(const wchar_t** data, std::wstring& str);
	static double ParseInt(const wchar_t** data);
	static double ParseDecimal(const wchar_t** data);
private:
	JsonParser();
};

// Simple function to check a string 's' has at least 'n' characters
static inline bool simplejson_wcsnlen(const wchar_t* s, size_t n)
{
	if (s == 0)
	{
		return false;
	}
	const wchar_t* save = s;
	while (n-- > 0)
	{
		if (*(save++) == 0)
		{
			return false;
		}
	}
	return true;
}