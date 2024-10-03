// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog
// (https://www.datadoghq.com/).
// Copyright 2019-present Datadog, Inc.

#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <tchar.h>
#include <thread>
#include <cstdlib>
#include <Windows.h>
#include <chrono>
#include "Process.h"
#include "Service.h"
#include "Win32Exception.h"

namespace
{
    // Synchronizes the reception of the CTRL signal
    HANDLE CtrlSignalReceivedEvent = INVALID_HANDLE_VALUE;

    const std::wstring TRUE_STR = L"TRUE";

    // The keys between service and entrypoints must be unique
    const std::map<std::wstring, std::filesystem::path> services =
    {
        {L"datadogagent", L"C:\\ProgramData\\Datadog\\logs\\agent.log"},
        {L"datadog-process-agent", L"C:\\ProgramData\\Datadog\\logs\\process-agent.log"},
        {L"datadog-trace-agent", L"C:\\ProgramData\\Datadog\\logs\\trace-agent.log"},
        {L"datadog-security-agent", L"C:\\ProgramData\\Datadog\\logs\\security-agent.log"},
    };

    std::string FormatErrorCode(DWORD errorCode)
    {
        std::stringstream sstream;
        sstream << "[" << errorCode << " (0x" << std::hex << errorCode << ")]";
        return sstream.str();
    }

    std::chrono::seconds service_timeout = std::chrono::seconds(30); // Default Windows value
}

const std::wstring GetEnvVar(std::wstring const& name)
{
    _TCHAR* buf = nullptr;
    size_t sz = 0;
    std::wstring val;
    if (_wdupenv_s(&buf, &sz, name.c_str()) == 0 && buf != nullptr)
    {
        val.assign(buf);
        free(buf);
    }

    return val;
}

BOOL WINAPI CtrlHandle(DWORD dwCtrlType)
{
    switch (dwCtrlType)
    {
    case CTRL_C_EVENT:
    case CTRL_CLOSE_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_LOGOFF_EVENT:
    case CTRL_SHUTDOWN_EVENT:
        std::cout << "[ENTRYPOINT][INFO] CTRL signal received, shutting down..." << std::endl;
        SetEvent(CtrlSignalReceivedEvent);
        break;

    default:
        break;
    }

    return TRUE;
}

void ExecuteInitScripts()
{
    auto directoryIt = std::filesystem::directory_iterator("entrypoint-ps1");
    for (auto& script : directoryIt)
    {
        Process pwsh = Process::Create(L"pwsh " + script.path().wstring());
        std::cout << "[ENTRYPOINT][INFO] Running init script: " << script.path().string() << std::endl;
        DWORD exitCode = pwsh.WaitForExit();
        if (exitCode != 0)
        {
            std::stringstream sstream;
            sstream << script.path() << " exited with code " << FormatErrorCode(exitCode);
            throw std::exception(sstream.str().c_str());
        }
    }
}

std::ifstream::pos_type StreamLogFromLastPosition(std::filesystem::path const& logFilePath, std::ifstream::pos_type lastPosition)
{
    char buffer[1024];
    // _SH_DENYNO: Share read and write access, so as not to conflict
    // with the agent's logging.
    // see https://docs.microsoft.com/en-us/cpp/c-runtime-library/reference/fsopen-wfsopen?view=vs-2017
    std::ifstream logFile(logFilePath, std::ios_base::in, _SH_DENYNO);
    if (logFile)
    {
        logFile.seekg(0, std::ifstream::end);
        auto fpos = logFile.tellg();
        if (lastPosition > fpos)
        {
            // New file
            lastPosition = 0;
        }
        logFile.seekg(lastPosition);

        const size_t totalToRead = fpos - lastPosition;
        size_t read = 0;
        while (read < totalToRead)
        {
            const size_t toRead = min(sizeof(buffer) / sizeof(char), totalToRead - read);
            logFile.read(buffer, toRead);
            std::cout.write(buffer, toRead);
            read += toRead;
        }

        lastPosition = fpos;
        logFile.close();
    }
    return lastPosition;
}

void StreamLogsToStdout(std::filesystem::path const& logFilePath)
{
    std::ifstream::pos_type lastPosition;
    while (true)
    {
        lastPosition = StreamLogFromLastPosition(logFilePath, lastPosition);
        Sleep(1000);
    }
}

void tryStopService(Service& service, const std::wstring& serviceName)
{
    try
    {
        service.Stop(service_timeout);
    }
    catch (...)
    {
        std::wcout << L"[ENTRYPOINT][ERROR] Could not stop " << serviceName << ". Trying to kill process." << std::endl;
        service.Kill(STATUS_TIMEOUT);
        throw;
    }
}

void RunService(std::wstring const& serviceName, std::filesystem::path const& logsPath)
{
    Service service(serviceName);
    std::wcout << L"[ENTRYPOINT][INFO] Starting service " << serviceName << std::endl;
    try
    {
        service.Start(service_timeout);
    }
    catch (...)
    {
        std::wcout << L"[ENTRYPOINT][ERROR] Could not start " << serviceName << L" (timeout)" << std::endl;
        tryStopService(service, serviceName);
        return;
    }
    std::wcout << L"[ENTRYPOINT][INFO] Success. Waiting for exit signal." << std::endl;
    std::thread logThread(StreamLogsToStdout, logsPath);
    logThread.detach();
    WaitForSingleObject(CtrlSignalReceivedEvent, INFINITE);
    std::wcout << L"[ENTRYPOINT][INFO] Stopping service " << serviceName << std::endl;
    tryStopService(service, serviceName);
}

void RunExecutable(std::wstring const& command)
{
    std::wcout << L"[ENTRYPOINT][INFO] Starting process " << command << std::endl;
    Process process = Process::Create(command);
    std::wcout << GetLastError() << std::endl;
    HANDLE events[2] =
    {
        // Process handle needs to be last so that WaitForMultipleObjects
        // would return our CtrlSignalReceivedEvent first in case they are signaled at the same time
        CtrlSignalReceivedEvent,
        process.GetProcessHandle()
    };
    const DWORD waitResult = WaitForMultipleObjects(2, events, FALSE, INFINITE);
    DWORD exitCode;
    if (waitResult == WAIT_FAILED)
    {
        throw Win32Exception("Failed to wait for objects");
    }

    if (waitResult == WAIT_OBJECT_0)
    {
        exitCode = process.WaitForExit(service_timeout);
    }
    else
    {
        exitCode = process.GetExitCode();
        SetEvent(CtrlSignalReceivedEvent);
    }
    std::wcout << L"[ENTRYPOINT][INFO] Command '" << command << L"' exited with code [0x" << std::hex << exitCode << L"]" << std::endl;
}

void Cleanup()
{
    CloseHandle(CtrlSignalReceivedEvent);
    CtrlSignalReceivedEvent = nullptr;
}

// Returns: 0 on success, -1 on error.
int _tmain(int argc, _TCHAR** argv)
{
    int exitCode = -1;

    auto command = GetEnvVar(L"ENTRYPOINT");
    if (argc <= 1 && command.empty())
    {
        std::cout << "Usage: entrypoint.exe <service> | <executable> <args>" << std::endl;
        return exitCode;
    }

    CtrlSignalReceivedEvent = CreateEvent(
        nullptr,            // default security attributes
        TRUE,               // manual-reset event
        FALSE,              // initial state is non-signaled
        nullptr             // object name
    );

    if (CtrlSignalReceivedEvent == nullptr)
    {
        std::cout << "[ENTRYPOINT][ERROR] Failed to create event with error: " << FormatErrorCode(GetLastError()) << std::endl;
        return exitCode;
    }

    if (!SetConsoleCtrlHandler(CtrlHandle, TRUE))
    {
        std::cout << "[ENTRYPOINT][ERROR] Failed to set control handle with error: " << FormatErrorCode(GetLastError()) << std::endl;
        Cleanup();
        return exitCode;
    }

    try
    {
        const auto runInitScripts = GetEnvVar(L"ENTRYPOINT_INITSCRIPTS");
        if (runInitScripts.empty() || runInitScripts == TRUE_STR)
        {
            ExecuteInitScripts();
        }

        // We checked earlier that argc >= 2 if command is empty
        if (command.empty())
        {
            command.assign(argv[1]);
        }

        // DD_SERVICE_STOP_TIMEOUT format is %Mm%Ss, so it matches 0m30s, 30m5s etc...
        std::wstringstream serviceTimeoutEnvVar(GetEnvVar(L"DD_SERVICE_TIMEOUT"));
        if (!serviceTimeoutEnvVar.view().empty())
        {
            // ReSharper disable once CppRedundantQualifier - legibility.
            serviceTimeoutEnvVar >> std::chrono::parse(L"%Mm%Ss", service_timeout);
            std::wcout << L"[ENTRYPOINT][INFO] DD_SERVICE_TIMEOUT = " << service_timeout << std::endl;
            if (service_timeout < std::chrono::seconds(30))
            {
                std::wcout << L"[ENTRYPOINT][WARNING] DD_SERVICE_TIMEOUT < 30s, resetting it to 30s to avoid causing issues with stopping dependent services" << std::endl;
                service_timeout = std::chrono::seconds(30);
            }
        }

        // Set the SCM timeout in the registry to be twice as long, that way we can handle shutting down the services ourselves
        HKEY controlKey;
        auto status = RegCreateKeyEx(
            HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Control",
            0,
            nullptr,
            REG_OPTION_NON_VOLATILE, KEY_WRITE | KEY_QUERY_VALUE,
            nullptr,
            &controlKey,
            nullptr
        );
        if (status != ERROR_SUCCESS)
        {
            throw std::exception("failed to open registry");
        }
        const DWORD servicesPipeTimeout = static_cast<DWORD>(std::chrono::duration_cast<std::chrono::milliseconds>(service_timeout).count() * 2);
        status = RegSetValueEx(
            controlKey,
            L"ServicesPipeTimeout",
            0,
            REG_DWORD,
            reinterpret_cast<const BYTE*>(&servicesPipeTimeout),
            sizeof servicesPipeTimeout
        );
        if (status != ERROR_SUCCESS)
        {
            throw std::exception("Setting key value failed.");
        }

        auto svcIt = services.find(command);
        if (svcIt != services.end())
        {
            RunService(svcIt->first, svcIt->second);
        }
        else
        {
            std::wstringstream commandLine;
            commandLine << command;
            for (int i = 2; i < argc; ++i)
            {
                commandLine << L" " << argv[i];
            }
            RunExecutable(commandLine.str());
        }
        exitCode = 0;
    }
    catch (Win32Exception& ex)
    {
        std::cout << "[ENTRYPOINT][ERROR] " << ex.what() << ". Error: " << FormatErrorCode(ex.GetErrorCode()) << std::endl;
    }
    catch (std::exception& ex)
    {
        std::cout << "[ENTRYPOINT][ERROR] " << ex.what() << std::endl;
    }
    catch (...)
    {
        std::cout << "[ENTRYPOINT][ERROR] Unexpected exception caught" << std::endl;
    }

    Cleanup();
    return exitCode;
}
