#pragma once
#include <string>
#include <vector>
#include "json_parser.h"

class JsonParser;

enum JsonType 
{ 
	JSONType_Null, 
	JSONType_String, 
	JSONType_Bool, 
	JSONType_Number, 
	JSONType_Array, 
	JSONType_Object 
};

class JsonValue
{
	friend class JsonParser;
public:
	JsonValue();
	JsonValue(const wchar_t* m_char_value);
	JsonValue(const std::wstring& m_string_value);
	JsonValue(bool m_bool_value);
	JsonValue(double m_number_value);
	JsonValue(int m_integer_value);
	JsonValue(const JsonArray& m_array_value);
	JsonValue(const JsonObject& m_object_value);
	JsonValue(const JsonValue& m_source);
	~JsonValue();

	JsonType GetType() const;
	bool IsNull() const;
	bool IsString() const;
	bool IsBool() const;
	bool IsNumber() const;
	bool IsArray() const;
	bool IsObject() const;

	const std::wstring& AsString() const;
	bool AsBool() const;
	double AsNumber() const;
	const JsonArray& AsArray() const;
	const JsonObject& AsObject() const;

	std::size_t CountChildren() const;
	bool HasChild(std::size_t index) const;
	JsonValue* Child(std::size_t index);
	bool HasChild(const wchar_t* name) const;
	JsonValue* Child(const wchar_t* name);
	std::vector<std::wstring> ObjectKeys() const;
	std::wstring Stringify(bool const prettyprint = false) const;
protected:
	static JsonValue* Parse(const wchar_t** data);

private:
	static std::wstring StringifyString(const std::wstring& str);
	std::wstring StringifyImpl(size_t const indentDepth) const;
	static std::wstring Indent(size_t depth);
	JsonType type;
	union
	{
		bool bool_value;
		double number_value;
		std::wstring* string_value;
		JsonArray* array_value;
		JsonObject* object_value;
	};
};