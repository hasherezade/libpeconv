#pragma once

#ifdef UNICODE
#define tcout wcout
#define tcerr wcerr
#define tstring wstring
#else
#define tcout cout
#define tcerr cerr
#define tstring string
#endif // UNICODE
