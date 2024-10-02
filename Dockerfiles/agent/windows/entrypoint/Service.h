// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog
// (https://www.datadoghq.com/).
// Copyright 2019-present Datadog, Inc.

#pragma once
#include <Windows.h>
#include <string>
#include <chrono>
#include <functional>
#include <memory>

class Service
{
private:
    typedef std::vector<std::unique_ptr<Service>> service_ptr;

    SC_HANDLE _scManagerHandle;
    SC_HANDLE _serviceHandle;
    DWORD _processId;

    [[nodiscard]]
    auto getDependentServices() const -> service_ptr;
    auto loopWaitServiceStatusPredicate(const std::function<bool(const SERVICE_STATUS_PROCESS&)> &predicate) const -> void;
public:
    explicit Service(std::wstring const& name);
    Service(Service&&) = default;
    Service(Service const&) = delete;
    ~Service();

    /**
     * \brief Attempts to start the service.
     * \param timeout How long the service has to comply.
     */
    void Start(std::chrono::milliseconds timeout = std::chrono::seconds(60));

    /**
     * \brief Attempts to stop the service and its dependent services.
     * \param timeout How long each service have to comply.
     * \note Since each service is given the same timeout and are being stopped serially,
     * the overall operation may take longer than the timeout value.
     */
    void Stop(std::chrono::milliseconds timeout = std::chrono::seconds(30));

    /**
     * \brief Kills the Process associated with this service.
     * \param exitCode the exit code to return.
     * \note This will also attempt to kill all the dependent services.
     * Prefer using Stop() to stop cleanly the service and its dependencies.
     */
    void Kill(UINT exitCode);
};

