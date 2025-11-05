# TraceLogger
TraceLogger is a C++ library that supports logging for programs and applications.
## Logging Levels
* **LOG_NONCE**: If this level is set, the function log displays the line number and log messages
* **LOG_DEBUG**: If this level is set, the function log displays the line number, function name and log messages
* **LOG_INFO**: If this level is set, the function log displays the line number, function name and log messages
* **LOG_WARNING**: If this level is set, the function log displays the line number, function name and log messages
* **LOG_ERROR**: If this level is set, the function log displays the line number, function name, file name and log messages
* **LOG_SUCCESS**: If this level is set, the function log displays the line number, function name, file name and log messages
* **LOG_CRITICAL**: If this level is set, the function log displays the line number, function name, file name and log messages
## Output
* **SHOW_MESSAGE**: This level will only write a simple message to the console.
* **SHOW_CONSOLE**: This level will provide detailed information such as the current time, line number, thread ID, function name, file name, and the log message to the console.
* **OUTPUT_DEBUG**: This level will write the log message to the debugger output.
* **WRITE_TO_FILE**: This level will write the log data to a file.
### Enable/Disable trace and log
```c++
    TraceLogger::instance()->EnableLog(BOOL);
    TraceLogger::instance()->EnableTrace(BOOL);
```
### Set log function output (Console, Write file, Output debug)
```c++
    TraceLogger::instance()->SetLogOut(LOG_OPTION);
```
### Set log level
```c++
    TraceLogger::instance()->SetLogLevel(LOG_LEVEL);
```
### Module log
```c++
    TraceLogger::instance()->LogA(__LINE__,"Text: %c %d \n", 'a', 65);
    TraceLogger::instance()->DebugA(__FUNCTION__,__LINE__,"Text: %c %d \n", 'a', 65);
    TraceLogger::instance()->InfoA(__FUNCTION__,__LINE__,"Text: %c %d \n", 'a', 65);
    TraceLogger::instance()->WarningA(__FUNCTION__,__LINE__,"Text: %c %d \n", 'a', 65);
    TraceLogger::instance()->ErrorA(__FUNCTION__,__LINE__,__FILE__,"Text: %c %d \n", 'a', 65);
    TraceLogger::instance()->SuccessA(__FUNCTION__,__LINE__,__FILE__,"Text: %c %d \n", 'a', 65);
    TraceLogger::instance()->CriticalA(__FUNCTION__,__LINE__,__FILE__,"Text: %c %d \n", 'a', 65);

    TraceLogger::instance()->LogW(__LINE__,L"Text: %c %d \n", 'a', 65);
    TraceLogger::instance()->DebugW(__FUNCTION__,__LINE__,L"Text: %c %d \n", 'a', 65);
    TraceLogger::instance()->InfoW(__FUNCTION__,__LINE__,L"Text: %c %d \n", 'a', 65);
    TraceLogger::instance()->WarningW(__FUNCTION__,__LINE__,L"Text: %c %d \n", 'a', 65);
    TraceLogger::instance()->ErrorW(__FUNCTION__,__LINE__,__FILE__,L"Text: %c %d \n", 'a', 65);
    TraceLogger::instance()->SuccessW(__FUNCTION__,__LINE__,__FILE__,L"Text: %c %d \n", 'a', 65);
    TraceLogger::instance()->CriticalW(__FUNCTION__,__LINE__,__FILE__,L"Text: %c %d \n", 'a', 65);
```
## Macro
### Enable/Disable trace and log
```c++
    ENABLE_LOG(BOOL);
    ENABLE_TRACE(BOOL);
```
### Set log function output (Console, Write file, Output debug)
```c++
    SET_LOG_OUT(LOG_OPTION);      
```
### Set log level
```c++
    SET_LOG_LEVEL(LOG_LEVEL);
```
### Module log
```c++
    LOG_A_("TEST LOG MACRO");
    LOG_DEBUG_A_("Level %d", 1);
    LOG_INFO_A_("Level %d", 2);
    LOG_WARNING_A("Level %d", 3);
    LOG_ERROR_A("Level %d", 4);
    LOG_SUCCESS_A("Level %d", 5);
    LOG_CRITICAL_A("Level % d", 6);

    TRACE_W(L"TEST TRACE MACRO");
    TRACE_IN_W(L"Number = %d", n);
    TRACE_OUT_W(L"Number = %d", n);
    TRACE_CALL_W(function, param);
```
#### Usage samples
```c++
int factorial(int n, double m, string str) {
    int res = 1;
    TraceLogger::instance()->TraceInA(__FUNCTION__, __LINE__, "n = %d", n);
    if (n > 1) {
        res = n * factorial(n - 1, m, str);
    }
    TraceLogger::instance()->TraceOutA(__FUNCTION__, __LINE__, "res = %d", res);
    return res;
}

int main()
{
    TraceLogger::instance()->EnableLog(TRUE);
    TraceLogger::instance()->SetLogOut(SHOW_CONSOLE);
    TraceLogger::instance()->SetLogLevel(LOG_CRITICAL);
    
    TraceLogger::instance()->LogA(__LINE__, "TEST LOG FUNCTION");
    TraceLogger::instance()->DebugW(__FUNCTION__,__LINE__, L"Level %d", 1);
    TraceLogger::instance()->InfoA(__FUNCTION__,__LINE__, "Level %d", 2);
    TraceLogger::instance()->WarningW(__FUNCTION__,__LINE__, L"Level %d", 3);
    TraceLogger::instance()->ErrorA(__FUNCTION__,__LINE__,__FILE__, "Level %d", 4);
    TraceLogger::instance()->SuccessW(__FUNCTION__,__LINE__,__FILE__, L"Level %d", 5);
    TraceLogger::instance()->CriticalA(__FUNCTION__, __LINE__, __FILE__, "Level %d", 6);

    TraceLogger::instance()->EnableTrace(TRUE);
    TraceLogger::instance()->TraceA("TEST TRACE FUNCTION");
    TraceLogger::instance()->TraceCallA(__FUNCTION__,__LINE__,__FILE__,factorial, 3, 3, "Hello");

    return 0;
}

```

#### Usage samples
```c++
int factorial(int n, double m, string str) {
    int res = 1;
    TRACE_IN("n = %d", n);
    if (n > 1) {
        res = n * factorial(n - 1, m, str);
    }
    TRACE_OUT("res = %d", res);
    return res;
int main()
{
    ENABLE_LOG(TRUE);
    SET_LOG_OUT(SHOW_CONSOLE);
    SET_LOG_LEVEL(LOG_CRITICAL);

    LOG_A("TEST LOG MACRO");
    LOG_DEBUG_W(L"Level %d", 1);
    LOG_INFO_A("Level %d", 2);
    LOG_WARNING_W(L"Level %d", 3);
    LOG_ERROR_A("Level %d", 4);
    LOG_SUCCESS_W(L"Level %d", 5);
    LOG_CRITICAL_A("Level %d", 6);
    
    ENABLE_TRACE(TRUE);
    TRACE_W(L"TEST TRACE MACRO");
    TRACE_CALL_A(factorial, 3, 2.5, "Hello");

    return 0;
}
```
