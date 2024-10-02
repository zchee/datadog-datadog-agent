// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog
// (https://www.datadoghq.com/).
// Copyright 2019-present Datadog, Inc.

#include "Service.h"
#include "Win32Exception.h"

namespace
{
    auto heapFree = [](LPENUM_SERVICE_STATUS p) { HeapFree(GetProcessHeap(), 0, p); };
    typedef std::unique_ptr<ENUM_SERVICE_STATUS, decltype(heapFree)> ENUM_SERVICE_STATUS_PTR;
}

SERVICE_STATUS_PROCESS getServiceStatus(SC_HANDLE serviceHandle)
{
    SERVICE_STATUS_PROCESS serviceStatus;
    DWORD unused = 0;
    if (!QueryServiceStatusEx(serviceHandle,
        SC_STATUS_PROCESS_INFO,
        reinterpret_cast<LPBYTE>(&serviceStatus),
        sizeof(SERVICE_STATUS_PROCESS),
        &unused))
    {
        throw Win32Exception("Could not query the service status");
    }
    return serviceStatus;
}

Service::Service(std::wstring const& name)
: _scManagerHandle(OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT))
, _serviceHandle(nullptr)
, _processId(0)
{
    if (_scManagerHandle == nullptr)
    {
        throw Win32Exception("Could not open the service control manager");
    }
    _serviceHandle = OpenService(
        _scManagerHandle,
        name.c_str(),
        SERVICE_START | SERVICE_STOP | SERVICE_QUERY_STATUS | SERVICE_ENUMERATE_DEPENDENTS);
    if (_serviceHandle == nullptr)
    {
        throw Win32Exception("Could not open the service");
    }

    const auto serviceStatus = getServiceStatus(_serviceHandle);
    // If the service was already started, then we can get its process ID
    _processId = serviceStatus.dwProcessId;
}

Service::~Service()
{
    CloseServiceHandle(_scManagerHandle);
    CloseServiceHandle(_serviceHandle);
}

auto Service::loopWaitServiceStatusPredicate(const std::function<bool(const SERVICE_STATUS_PROCESS &)> &predicate) const -> void
{
    do
    {
        const auto serviceStatus = getServiceStatus(_serviceHandle);
        if (predicate(serviceStatus))
        {
            break;
        }

        Sleep(1000);
    }
    while (true);
}

auto Service::getDependentServices() const -> service_ptr
{
    DWORD sizeNeededDependentServices;
    DWORD countDependentServices;
    std::vector<std::unique_ptr<Service>> services;

    if (!EnumDependentServices(
        _serviceHandle,
        SERVICE_ACTIVE,
        nullptr,
        0,
        &sizeNeededDependentServices,
        &countDependentServices))
    {
        // If the Enum call fails, then there are dependent services to be stopped first
        if (GetLastError() != ERROR_MORE_DATA)
        {
            // The last error must be ERROR_MORE_DATA
            throw Win32Exception("Unexpected error while fetching dependent services");
        }

        ENUM_SERVICE_STATUS_PTR depSvcs(
            static_cast<LPENUM_SERVICE_STATUS>(
                HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeNeededDependentServices)), heapFree);

        if (!EnumDependentServices(
            _serviceHandle,
            SERVICE_ACTIVE,
            depSvcs.get(),
            sizeNeededDependentServices,
            &sizeNeededDependentServices,
            &countDependentServices))
        {
            throw Win32Exception("Could not enumerate dependent services");
        }
        for (DWORD i = 0; i < countDependentServices; ++i)
        {
            services.emplace_back(std::make_unique<Service>(depSvcs.get()[i].lpServiceName));
        }
    }
    return services;
}

void Service::Start(std::chrono::milliseconds timeout)
{
    if (!StartService(_serviceHandle, 0, nullptr))
    {
        const DWORD lastError = GetLastError();
        if (lastError != ERROR_SERVICE_ALREADY_RUNNING)
        {
            throw Win32Exception("Could not start the service");
        }
    }

    loopWaitServiceStatusPredicate([this, &timeout](const SERVICE_STATUS_PROCESS& serviceStatus)
    {
        if (_processId == 0)
        {
            _processId = serviceStatus.dwProcessId;
        }

        if (serviceStatus.dwCurrentState == SERVICE_RUNNING)
        {
            // Stop the loop
            return true;
        }
        timeout -= std::chrono::seconds(1);
        if (timeout.count() <= 0)
        {
            throw std::exception("Timeout while starting the service");
        }
        return false;
    });
}

void Service::Stop(std::chrono::milliseconds timeout)
{
    // Wait for the service to settle
    loopWaitServiceStatusPredicate([this](const SERVICE_STATUS_PROCESS& serviceStatus)
    {
        return !(serviceStatus.dwCurrentState == SERVICE_STOP_PENDING || serviceStatus.dwCurrentState == SERVICE_START_PENDING);
    });

    const auto depSvc = getDependentServices();
    for (auto& svc : depSvc)
    {
        // Note that by giving dependent services the same timeout
        // we may exceed our timeout ourselves.
        // Note bis: if one of the dependent services fails to stop
        // this will throw, and the entrypoint will kill the process.
        svc->Stop(timeout);
    }

    SERVICE_STATUS_PROCESS serviceStatus;
    if (!ControlService(_serviceHandle, SERVICE_CONTROL_STOP, reinterpret_cast<LPSERVICE_STATUS>(&serviceStatus)))
    {
        if (serviceStatus.dwCurrentState == SERVICE_STOPPED)
        {
            // Service is already shut down
            return;
        }
        throw Win32Exception("Could not stop the service");
    }

    loopWaitServiceStatusPredicate([this, &timeout](const SERVICE_STATUS_PROCESS& serviceStatus)
    {
        if (serviceStatus.dwCurrentState == SERVICE_STOPPED)
        {
            // Stop the loop
            return true;
        }

        auto waitTime = std::chrono::milliseconds(serviceStatus.dwWaitHint) / 10;
        if (waitTime < std::chrono::seconds(1))
        {
            waitTime = std::chrono::seconds(1);
        }
        else if (waitTime > std::chrono::seconds(10))
        {
            waitTime = std::chrono::seconds(10);
        }
        Sleep(static_cast<DWORD>(waitTime.count()));
        timeout -= waitTime;
        if (timeout.count() <= 0)
        {
            throw std::exception("Timeout while stopping the service");
        }

        return false;
    });
}

void Service::Kill(UINT exitCode)
{
    const auto depSvc = getDependentServices();
    for (const auto& svc : depSvc)
    {
        svc->Kill(exitCode);
    }
    TerminateProcess(OpenProcess(PROCESS_ALL_ACCESS, FALSE, _processId), exitCode);
}
