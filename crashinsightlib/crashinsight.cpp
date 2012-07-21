// crashinsight.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

#include <vector>
#include <map>
#include <string>
#include <algorithm>
#include <iostream>
#include <iomanip>


#include <boost/filesystem.hpp>
#include <boost/regex.hpp>


#include <windows.h>
#include <winternl.h>

#include <initguid.h>
#include <cguid.h>
#include <dbgeng.h>


#pragma comment(lib, "dbgeng.lib")

#include <atlbase.h>

#include "crashinsight.h"

#define RETONFAILED(x, __VARARGS__) if(FAILED(x = __VARARGS__)){ std::cerr << __FILE__ << "(" << __LINE__ << "): " << x << std::endl; return x; }

class CComInit
{
public:
    CComInit()
    {
    }

    HRESULT Init()
    {
        return CoInitialize(NULL);
    }

    ~CComInit()
    {
        CoUninitialize();
    }
};





// http://blogs.msdn.com/b/joshpoley/archive/2008/05/27/opening-a-crash-dump-file-automating-crash-dump-analysis-part-1.aspx
// http://blogs.msdn.com/b/joshpoley/archive/2008/06/23/automating-crash-dump-analysis-some-final-thoughts.aspx

char const * const GetExceptionName(int i)
{
    switch (i)
    {
    case EXCEPTION_ACCESS_VIOLATION               : return "EXCEPTION_ACCESS_VIOLATION";
    case EXCEPTION_ARRAY_BOUNDS_EXCEEDED          : return "EXCEPTION_ARRAY_BOUNDS_EXCEEDED";
    case EXCEPTION_BREAKPOINT                     : return "EXCEPTION_BREAKPOINT";
    case EXCEPTION_DATATYPE_MISALIGNMENT          : return "EXCEPTION_DATATYPE_MISALIGNMENT";
    case EXCEPTION_FLT_DENORMAL_OPERAND           : return "EXCEPTION_FLT_DENORMAL_OPERAND";
    case EXCEPTION_FLT_DIVIDE_BY_ZERO             : return "EXCEPTION_FLT_DIVIDE_BY_ZERO";
    case EXCEPTION_FLT_INEXACT_RESULT             : return "EXCEPTION_FLT_INEXACT_RESULT";
    case EXCEPTION_FLT_INVALID_OPERATION          : return "EXCEPTION_FLT_INVALID_OPERATION";
    case EXCEPTION_FLT_OVERFLOW                   : return "EXCEPTION_FLT_OVERFLOW";
    case EXCEPTION_FLT_STACK_CHECK                : return "EXCEPTION_FLT_STACK_CHECK";
    case EXCEPTION_FLT_UNDERFLOW                  : return "EXCEPTION_FLT_UNDERFLOW";
    case EXCEPTION_ILLEGAL_INSTRUCTION            : return "EXCEPTION_ILLEGAL_INSTRUCTION";
    case EXCEPTION_IN_PAGE_ERROR                  : return "EXCEPTION_IN_PAGE_ERROR";
    case EXCEPTION_INT_DIVIDE_BY_ZERO             : return "EXCEPTION_INT_DIVIDE_BY_ZERO";
    case EXCEPTION_INT_OVERFLOW                   : return "EXCEPTION_INT_OVERFLOW";
    case EXCEPTION_INVALID_DISPOSITION            : return "EXCEPTION_INVALID_DISPOSITION";
    case EXCEPTION_NONCONTINUABLE_EXCEPTION       : return "EXCEPTION_NONCONTINUABLE_EXCEPTION";
    case EXCEPTION_PRIV_INSTRUCTION               : return "EXCEPTION_PRIV_INSTRUCTION";
    case EXCEPTION_SINGLE_STEP                    : return "EXCEPTION_SINGLE_STEP";
    case EXCEPTION_STACK_OVERFLOW                 : return "EXCEPTION_STACK_OVERFLOW";
    }

    return NULL;
}

HRESULT DumpBugCheck(IDebugControl *control, IDebugSymbols *symbols)
{
    HRESULT hr           = S_OK;

    ULONG bugCheckCode = 0;
    ULONG64 bugCheckArgs[4] = {0};

    // look for Bug Check data
    hr = control->ReadBugCheckData(&bugCheckCode, &bugCheckArgs[0], &bugCheckArgs[1],
        &bugCheckArgs[2], &bugCheckArgs[3]);

    if(SUCCEEDED(hr))
    {
        printf("  Bug Check:         %X (0x%08X, 0x%08X, 0x%08X, 0x%08X)\n",
            bugCheckCode, bugCheckArgs[0], bugCheckArgs[1],
            bugCheckArgs[2], bugCheckArgs[3]);
    }

    return hr;
}

std::string to_hex_string( DWORD64 ExceptionCode ) 
{
    std::stringstream ss;

    ss << "0x" << std::setw(8) << std::setfill('0') << std::hex << ExceptionCode;

    return ss.str();
}



HRESULT PrintStackEx(IDebugSymbols *symbols, IDebugClient *client, IDebugControl *control, std::ostream &os)
{
    HRESULT hr = S_OK;

    CComPtr<IDebugAdvanced2> advanced2;
    RETONFAILED(hr, client->QueryInterface(IID_IDebugAdvanced2, (PVOID*)&advanced2.p));

    CComPtr<IDebugControl4> control4;
    RETONFAILED(hr, control->QueryInterface(IID_IDebugControl4, (PVOID*)&control4.p));

    CONTEXT _context = { 0 };
    ULONG _uOutSize = 0;

    RETONFAILED(hr, advanced2->Request(DEBUG_REQUEST_TARGET_EXCEPTION_CONTEXT, NULL, 0, &_context, sizeof(CONTEXT), &_uOutSize));

    DEBUG_STACK_FRAME _stackFrames[256] = { 0 };
    CONTEXT _frameContexts[256] = { 0 };
    ULONG _uFramesFilled = 0;

    RETONFAILED(hr, control4->GetContextStackTrace(&_context, sizeof(_context), _stackFrames, ARRAYSIZE(_stackFrames),
        _frameContexts, 256 * sizeof(CONTEXT), sizeof(CONTEXT), &_uFramesFilled));

    for( ULONG _uFrame = 0; _uFrame < _uFramesFilled; _uFrame++ ) {
        HRESULT symhr;
        char _name[512];
        unsigned __int64 offset = 0;
        ULONG _uLineNo = 0;

        ZeroMemory(_name, ARRAYSIZE(_name));
        symhr = symbols->GetNameByOffset(_stackFrames[_uFrame].InstructionOffset,
            _name, ARRAYSIZE(_name) - 1, NULL, &offset);

        char buf[1024] = {0};
        if(SUCCEEDED(symhr)) {
            sprintf(buf, "%s+0x%I64X", _name, offset);
        } else {
            sprintf(buf, "0x%08I64X", _stackFrames[_uFrame].InstructionOffset);
        }

        os << buf;

        ZeroMemory(_name, ARRAYSIZE(_name));
        symhr = symbols->GetLineByOffset(_stackFrames[_uFrame].InstructionOffset,
            &_uLineNo, _name, ARRAYSIZE(_name) - 1, NULL, NULL);

        if(SUCCEEDED(symhr)) {
            os << _name << "(" << _uLineNo << ")";
        }
        os << std::endl;
    }

    return hr;
}

void process_zero_separated_string( const WCHAR * buff )
{
    const WCHAR * p = buff;
    size_t len = wcslen(buff);

    while( *p != L'\0' ) {
        const WCHAR * pe = wcsstr(p, L"=");
        
        std::wstring a(p, pe);

        pe += 1;

        const WCHAR * pee = pe + wcslen(pe);
        std::wstring b(pe, pee );

        p = pee + 1;

        auto pair = std::make_pair(a, b);
    }
}

HRESULT process_peb(IDebugClient * client ) 
{
    HRESULT hr = S_OK;

    CComPtr<IDebugRegisters2> registers;
    RETONFAILED(hr, client->QueryInterface(IID_IDebugRegisters2, (LPVOID*)&registers.p));

    ULONG Number = 0;
    RETONFAILED(hr, registers->GetNumberRegisters(&Number));

    for(ULONG i = 0; i < Number; i++) {
        CHAR name[256] = {0};

        DEBUG_REGISTER_DESCRIPTION desc = {0};
        ULONG nameSize = 0;
        RETONFAILED(hr, registers->GetDescription(i, name, ARRAYSIZE(name), &nameSize, &desc));

        int a = 0;
    }

    RETONFAILED(hr, registers->GetNumberPseudoRegisters(&Number));

    for(ULONG i = 0; i < Number; i++) {
        CHAR name[256] = {0};

        DEBUG_REGISTER_DESCRIPTION desc = {0};
        ULONG nameSize = 0;
        hr = registers->GetPseudoDescription (i, name, ARRAYSIZE(name), &nameSize, NULL, NULL);

        int a = 0;
    }

    ULONG index = 0;
    RETONFAILED(hr, registers->GetPseudoIndexByName("$peb", &index));

    DEBUG_VALUE value = {0};
    RETONFAILED(hr, registers->GetValue(index, &value));

    RETONFAILED(hr, registers->GetPseudoValues(DEBUG_REGSRC_DEBUGGEE, 1, &index, 0, &value));


    {
        CComPtr<IDebugDataSpaces> data;
        RETONFAILED(hr, client->QueryInterface(IID_IDebugDataSpaces, (LPVOID*)&data.p));

        USHORT SizeEProcess = 0;
        RETONFAILED(hr, data->ReadDebuggerData(DEBUG_DATA_SizeEProcess, &SizeEProcess, sizeof(SizeEProcess), NULL));

        USHORT OffsetEprocessPeb = 0;
        RETONFAILED(hr, data->ReadDebuggerData(DEBUG_DATA_OffsetEprocessPeb, &OffsetEprocessPeb, sizeof(OffsetEprocessPeb), NULL));

        PEB peb = {0};
        ULONG read = 0;

        RETONFAILED(hr, data->ReadVirtual(value.I64, &peb, sizeof(peb), &read));

        char buf_rtl[4*1024] = {0};

        RETONFAILED(hr, data->ReadVirtual((ULONG64)peb.ProcessParameters, &buf_rtl, sizeof(buf_rtl), &read));

        RTL_USER_PROCESS_PARAMETERS& parameters = (RTL_USER_PROCESS_PARAMETERS&)buf_rtl;

        WCHAR buf[1024] = {0};

        RETONFAILED(hr, data->ReadVirtual((ULONG64)parameters.ImagePathName.Buffer, buf, sizeof(buf), &read));

        void* p = *(void**)(((char*)&parameters) + 0x80);

        WCHAR term[] = L"\0\0";

        ULONG64 offset = 0;

        hr = data->SearchVirtual((ULONG64)p, 10*1024, term, sizeof(term), 1, &offset);

        WCHAR buff[10*1024] = {0};
        hr = data->ReadVirtual((ULONG64)p, buff, (ULONG)offset - (ULONG)p, &read);

        process_zero_separated_string(&buff[0]);
        
        for(int j = 0, n = ARRAYSIZE(parameters.Reserved2); j < n; j++) {

            char buff[1024] = {0};
            hr = data->ReadVirtual((ULONG64)parameters.Reserved2[j], buff, sizeof(buff), &read);

            int a = 0;
        }
    }

    return hr;
}	

HRESULT process_exception( dictionary &info, IDebugSymbols * symbols, IDebugClient * client, IDebugControl * control ) 
{
    HRESULT hr = S_OK;

    union ExtraInfo
    {
        DEBUG_LAST_EVENT_INFO_EXCEPTION exceptionInfo;
        // as needed, we can add more of the
        // DEBUG_LAST_EVENT_INFO_xyz structs here
    };

    ULONG type           = 0;
    ULONG procID         = 0;
    ULONG threadID       = 0;

    ExtraInfo extraInfo  = {};
    ULONG extraInfoUsed  = 0;
    char description[80] = {0};


    RETONFAILED(hr, control->GetLastEventInformation(&type, &procID, &threadID,
        &extraInfo, sizeof(extraInfo), &extraInfoUsed, description, ARRAYSIZE(description)-1, NULL));

    if( extraInfoUsed >= sizeof(extraInfo.exceptionInfo) )
    {
        // why the check
    }


    const EXCEPTION_RECORD64 *er = &extraInfo.exceptionInfo.ExceptionRecord;

    info.push_back(std::make_pair("code", to_hex_string( er->ExceptionCode ) ));

    char const * const exceptionName = GetExceptionName(er->ExceptionCode);
    info.push_back(std::make_pair("exception_name", nullptr == exceptionName ? "" : exceptionName));

    info.push_back(std::make_pair("address", to_hex_string(er->ExceptionAddress)));

    switch ( er->ExceptionCode ) {
    case EXCEPTION_ACCESS_VIOLATION:
    case EXCEPTION_IN_PAGE_ERROR:
        {
            if(er->ExceptionInformation[0] == 0) {
                info.push_back(std::make_pair("action", "read"));
                info.push_back(std::make_pair("dest", to_hex_string(er->ExceptionInformation[1])));
            } else if(er->ExceptionInformation[0] == 1) {
                info.push_back(std::make_pair("action", "write"));
                info.push_back(std::make_pair("dest", to_hex_string(er->ExceptionInformation[1])));
            } else if(er->ExceptionInformation[0] == 8) {
                info.push_back(std::make_pair("action", "user mode fault"));
                info.push_back(std::make_pair("dest", to_hex_string(er->ExceptionInformation[1])));
            }
        }break;
    }

    std::stringstream sstream;

    PrintStackEx(symbols, client, control, sstream);

    info.push_back(std::make_pair("callstack", sstream.str()));

    return hr;
}



HRESULT DumpEvent(dictionary &info, IDebugControl *control, IDebugClient *client, IDebugSymbols *symbols)
{
    HRESULT hr           = S_OK;
    ULONG type           = 0;
    ULONG procID         = 0;
    ULONG threadID       = 0;
    char description[80] = {0};


    // get the fault information
    RETONFAILED(hr, control->GetLastEventInformation(&type, &procID, &threadID,
        NULL, 0, NULL, description, ARRAYSIZE(description)-1, NULL));

    info.push_back(std::make_pair("description", description));

    ULONG ProcessorType = 0;
    RETONFAILED(hr, control->GetEffectiveProcessorType(&ProcessorType));

    switch( ProcessorType ) {
    case IMAGE_FILE_MACHINE_I386  : info.push_back(std::make_pair("cpu", "x86"));     break;
    case IMAGE_FILE_MACHINE_ARM   : info.push_back(std::make_pair("cpu", "arm"));     break;
    case IMAGE_FILE_MACHINE_IA64  : info.push_back(std::make_pair("cpu", "i64"));     break;
    case IMAGE_FILE_MACHINE_AMD64 : info.push_back(std::make_pair("cpu", "x64"));     break;
    case IMAGE_FILE_MACHINE_EBC   : info.push_back(std::make_pair("cpu", "ebc"));     break;
    default                       : info.push_back(std::make_pair("cpu", "unknown")); break;
    }

    switch( type ) {
    case DEBUG_EVENT_EXCEPTION:
        process_exception(info, symbols, client, control);
        break;
    }

    hr = process_peb(client);


    return hr;
}


HRESULT process_crash_dmp(const std::string &crashdmp, const po::variables_map &vm, dictionary &info )
{
    CComInit ci;

    HRESULT hr = E_FAIL;
    // Initialize COM
    RETONFAILED(hr, ci.Init());

    CComPtr<IDebugClient> client;
    CComPtr<IDebugControl> control;
    CComPtr<IDebugSymbols> symbols;

    // Create the base IDebugClient object
    RETONFAILED(hr, DebugCreate(IID_IDebugClient, (LPVOID*)&client.p));

    // from the base, create the Control and Symbols objects
    RETONFAILED(hr, client.QueryInterface(&control));

    RETONFAILED(hr, client.QueryInterface(&symbols));

    // we can supplement the _NT_SYMBOL_PATH environment variable by adding a path here
    if( vm.count("symbol_path") ) {
        RETONFAILED(hr, symbols->SetSymbolPath(vm["symbol_path"].as<std::string>().c_str()));
    }
    // the debugger will need to look at the actual binaries
    // so provide the path to the executable files
    if( vm.count("image_path") ) {
        RETONFAILED(hr, symbols->SetImagePath(vm["image_path"].as<std::string>().c_str()));
    }

    // open the crash dump
    RETONFAILED(hr, client->OpenDumpFile(crashdmp.c_str()));

    // wait for the engine to finish processing
    RETONFAILED(hr, control->WaitForEvent(DEBUG_WAIT_DEFAULT, INFINITE));

    // RETONFAILED(hr, PrintStackEx(symbols, client, control));


    RETONFAILED(hr, DumpEvent(info, control, client, symbols));

    return hr;
}


void find_dmp_files( const std::vector<std::string> & scan_dirs, std::vector<std::string> &crashdmps )
{
    std::vector<std::string> dirs = scan_dirs;

    while( dirs.size() ) {
        std::string dir = scan_dirs.front();
        dirs.erase(dirs.begin());
        //const boost::regex my_filter( "somefiles.*\.txt" );


        boost::filesystem::directory_iterator end_itr; // Default ctor yields past-the-end
        for( boost::filesystem::directory_iterator i( dir ); i != end_itr; ++i )
        {
            std::string pathname = i->path().string();

            if( boost::filesystem::is_directory( i->status() ) ) {
                dirs.push_back(i->path().string());
            }

            // Skip if not a file
            if( !boost::filesystem::is_regular_file( i->status() ) ) continue;

            //boost::smatch what;

            // Skip if no match
            //if( !boost::regex_match( i->leaf(), what, my_filter ) ) continue;
            if( i->path().extension() != ".dmp" ) 
                continue;

            // File matches, store it
            crashdmps.push_back( i->path().string() );
        }
    }
}




/*
int _tmain(int argc, _TCHAR* argv[])
{
    HRESULT hr = S_OK;

    po::variables_map vm;
    int iRet = process_command_line(argc, argv, vm);

    if( 0 != iRet ) {
        return iRet;
    }

    if( !vm.count("crash_dmp") && !vm.count("crash_dmp_scan_dir") ) {
        std::cout << "Invalid arguments for crash_dmp option" << std::endl;
        return -1;
    }

    std::vector<std::string> crash_dmp_paths;

    if( vm.count("crash_dmp") ) {
        crash_dmp_paths = vm["crash_dmp"].as<std::vector<std::string>>();
    } else {
        if( vm.count("crash_dmp_scan_dir") ) {
            std::vector<std::string> scan_dirs = vm["crash_dmp_scan_dir"].as<std::vector<std::string>>();

            find_dmp_files(scan_dirs, crash_dmp_paths);
        }
    }


    std::cout << "<crashdmps>" << std::endl;

    for( size_t i = 0, n = crash_dmp_paths.size(); i < n; i++ ) {
        dictionary info;

        const std::string &crashdmp = crash_dmp_paths[i];

        std::cerr << "Processing " << (i + 1) << "/" << n << ": " << crashdmp << "." << std::endl;

        info.push_back(std::make_pair("file", crashdmp));

        process_crash_dmp(crashdmp, vm, info);

        path_regex_extract(crashdmp, vm, info);

        std::cout << "<crashdmp ";
        std::for_each(info.begin(), info.end(), [](std::pair<std::string, std::string> & p){
            std::cout << p.first << "=\"" << xml_encode(p.second) << "\" ";
        });
        std::cout << "/>";
        std::cout << std::endl;
    }
    std::cout << "</crashdmps>" << std::endl;

    return hr;
}

*/
