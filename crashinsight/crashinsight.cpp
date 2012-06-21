// crashinsight.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

#include <windows.h>
#include "dbgeng.h"
#pragma comment(lib, "dbgeng.lib")


// http://blogs.msdn.com/b/joshpoley/archive/2008/05/27/opening-a-crash-dump-file-automating-crash-dump-analysis-part-1.aspx
// http://blogs.msdn.com/b/joshpoley/archive/2008/06/23/automating-crash-dump-analysis-some-final-thoughts.aspx

char const * const GetExceptionName(int i)
{
    switch (i)
    {
    case EXCEPTION_ACCESS_VIOLATION               : return "EXCEPTION_ACCESS_VIOLATION               ";
    case EXCEPTION_ARRAY_BOUNDS_EXCEEDED          : return "EXCEPTION_ARRAY_BOUNDS_EXCEEDED          ";
    case EXCEPTION_BREAKPOINT                     : return "EXCEPTION_BREAKPOINT                     ";
    case EXCEPTION_DATATYPE_MISALIGNMENT          : return "EXCEPTION_DATATYPE_MISALIGNMENT          ";
    case EXCEPTION_FLT_DENORMAL_OPERAND           : return "EXCEPTION_FLT_DENORMAL_OPERAND           ";
    case EXCEPTION_FLT_DIVIDE_BY_ZERO             : return "EXCEPTION_FLT_DIVIDE_BY_ZERO             ";
    case EXCEPTION_FLT_INEXACT_RESULT             : return "EXCEPTION_FLT_INEXACT_RESULT             ";
    case EXCEPTION_FLT_INVALID_OPERATION          : return "EXCEPTION_FLT_INVALID_OPERATION          ";
    case EXCEPTION_FLT_OVERFLOW                   : return "EXCEPTION_FLT_OVERFLOW                   ";
    case EXCEPTION_FLT_STACK_CHECK                : return "EXCEPTION_FLT_STACK_CHECK                ";
    case EXCEPTION_FLT_UNDERFLOW                  : return "EXCEPTION_FLT_UNDERFLOW                  ";
    case EXCEPTION_ILLEGAL_INSTRUCTION            : return "EXCEPTION_ILLEGAL_INSTRUCTION            ";
    case EXCEPTION_IN_PAGE_ERROR                  : return "EXCEPTION_IN_PAGE_ERROR                  ";
    case EXCEPTION_INT_DIVIDE_BY_ZERO             : return "EXCEPTION_INT_DIVIDE_BY_ZERO             ";
    case EXCEPTION_INT_OVERFLOW                   : return "EXCEPTION_INT_OVERFLOW                   ";
    case EXCEPTION_INVALID_DISPOSITION            : return "EXCEPTION_INVALID_DISPOSITION            ";
    case EXCEPTION_NONCONTINUABLE_EXCEPTION       : return "EXCEPTION_NONCONTINUABLE_EXCEPTION       ";
    case EXCEPTION_PRIV_INSTRUCTION               : return "EXCEPTION_PRIV_INSTRUCTION               ";
    case EXCEPTION_SINGLE_STEP                    : return "EXCEPTION_SINGLE_STEP                    ";
    case EXCEPTION_STACK_OVERFLOW                 : return "EXCEPTION_STACK_OVERFLOW                 ";
    }

    return NULL;
}

HRESULT DumpEvent(IDebugControl *control, IDebugSymbols *symbols)
{
    union ExtraInfo
    {
        DEBUG_LAST_EVENT_INFO_EXCEPTION exceptionInfo;
        // as needed, we can add more of the
        // DEBUG_LAST_EVENT_INFO_xyz structs here
    };

    HRESULT hr = S_OK;
    ULONG type = 0;
    ULONG procID = 0;
    ULONG threadID = 0;
    ExtraInfo extraInfo;
    ULONG extraInfoUsed = 0;
    char description[80] = {0};

    ULONG bugCheckCode = 0;
    ULONG64 bugCheckArgs[4] = {0};

    ZeroMemory(&extraInfo, sizeof(extraInfo));


    // look for Bug Check data
    hr = control->ReadBugCheckData(&bugCheckCode, &bugCheckArgs[0], &bugCheckArgs[1],
        &bugCheckArgs[2], &bugCheckArgs[3]);

    if(SUCCEEDED(hr))
    {
        printf("  Bug Check:         %X (0x%08X, 0x%08X, 0x%08X, 0x%08X)\n",
            bugCheckCode, bugCheckArgs[0], bugCheckArgs[1],
            bugCheckArgs[2], bugCheckArgs[3]);
    }

    // get the fault information
    hr = control->GetLastEventInformation(&type, &procID, &threadID,
        &extraInfo, sizeof(extraInfo), &extraInfoUsed, description,
        ARRAYSIZE(description)-1, NULL);

    if(FAILED(hr))
        goto cleanup;

    printf("  Description:       %s\n", description);

    // if we hit an exception, and we understand the type of exception, write
    // out some additional information
    if((type == DEBUG_EVENT_EXCEPTION) &&
        (extraInfoUsed >= sizeof(extraInfo.exceptionInfo)))
    {
        EXCEPTION_RECORD64 *er = &extraInfo.exceptionInfo.ExceptionRecord;
        printf("  Type:              %s\n", GetExceptionName(er->ExceptionCode));

        if(er->ExceptionCode == EXCEPTION_ACCESS_VIOLATION ||
            er->ExceptionCode == EXCEPTION_IN_PAGE_ERROR)
        {
            if(er->ExceptionInformation[0] == 0)
                printf("    Read at:         0x%08X\n", er->ExceptionInformation[1]);
            else if(er->ExceptionInformation[0] == 1)
                printf("    Write at:        0x%08X\n", er->ExceptionInformation[1]);
            else if(er->ExceptionInformation[0] == 8)
                printf("    User Mode Fault: 0x%08X\n", er->ExceptionInformation[1]);
        }
    }

cleanup:

    return hr;
}

int _tmain(int argc, _TCHAR* argv[])
{
    char *symbolPath = "c:\\myApp\\release";
    char *imagePath = "c:\\myApp\\release";
    char *crashPath = argv[1];

    HRESULT hr = E_FAIL;
    IDebugClient *client = NULL;
    IDebugControl *control = NULL;
    IDebugSymbols *symbols = NULL;

    // Initialize COM
    hr = CoInitialize(NULL);
    if(FAILED(hr))
        goto cleanup;

    // Create the base IDebugClient object
    hr = DebugCreate(__uuidof(IDebugClient), (LPVOID*)&client);
    if(FAILED(hr))
        goto cleanup;

    // from the base, create the Control and Symbols objects
    hr = client->QueryInterface(__uuidof(IDebugControl), (LPVOID*)&control);
    if(FAILED(hr))
        goto cleanup;

    hr = client->QueryInterface(__uuidof(IDebugSymbols), (LPVOID*)&symbols);
    if(FAILED(hr))
        goto cleanup;

    // we can supplement the _NT_SYMBOL_PATH environment variable
    // by adding a path here
    symbols->SetSymbolPath(symbolPath);

    // the debugger will need to look at the actual binaries
    // so provide the path to the exsecutable files
    symbols->SetImagePath(imagePath);

    // open the crash dump
    hr = client->OpenDumpFile(crashPath);
    if(FAILED(hr))
        goto cleanup;

    // wait for the engine to finish processing
    control->WaitForEvent(DEBUG_WAIT_DEFAULT, INFINITE);

    hr = DumpEvent(control, symbols);
    if(FAILED(hr))
        goto cleanup;


cleanup:

    // cleanup and destroy the objects
    if(symbols)
    {
        symbols->Release();
        symbols = NULL;
    }
    if(control)
    {
        control->Release();
        control = NULL;
    }
    if(client)
    {
        client->Release();
        client = NULL;
    }

    // cleanup COM
    CoUninitialize();

    return 0;
}