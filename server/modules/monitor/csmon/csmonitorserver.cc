/*
 * Copyright (c) 2018 MariaDB Corporation Ab
 *
 * Use of this software is governed by the Business Source License included
 * in the LICENSE.TXT file and at www.mariadb.com/bsl11.
 *
 * Change Date: 2024-03-10
 *
 * On the date above, in accordance with the Business Source License, use
 * of this software will be governed by version 2 or later of the General
 * Public License.
 */

#include "csmonitorserver.hh"
#include <maxbase/http.hh>
#include "csrest.hh"

namespace http = mxb::http;

CsMonitorServer::CsMonitorServer(SERVER* pServer,
                                 const SharedSettings& shared,
                                 int64_t admin_port)
    : mxs::MonitorServer(pServer, shared)
    , m_admin_port(admin_port)
{
}

CsMonitorServer::~CsMonitorServer()
{
}

bool CsMonitorServer::refresh_config(json_t** ppOutput)
{
    bool rv = false;
    http::Result result = http::get(cs::rest::create_url(*this->server, m_admin_port, cs::rest::CONFIG));

    if (result.code == 200)
    {
        rv = set_config(result.body, ppOutput);
    }
    else if (ppOutput)
    {
        PRINT_MXS_JSON_ERROR(ppOutput,
                             "Could not fetch config from '%s': %s",
                             this->server->name(), result.body.c_str());
    }

    return rv;
}

bool CsMonitorServer::set_config(const std::string& body, json_t** ppOutput)
{
    bool rv = false;

    json_error_t error;
    json_t* pConfig = json_loadb(body.c_str(), body.length(), 0, &error);

    if (pConfig)
    {
        json_t* pColumnstore = json_object_get(pConfig, cs::keys::COLUMNSTORE);

        if (pColumnstore)
        {
            // TODO: Parse XML.
            rv = true;
        }
        else if (ppOutput)
        {
            PRINT_MXS_JSON_ERROR(ppOutput,
                                 "Obtained config object, but it does not have a '%s' key.",
                                 cs::keys::COLUMNSTORE);
        }
    }
    else if (ppOutput)
    {
        PRINT_MXS_JSON_ERROR(ppOutput, "Could not parse JSON data from: %s", error.text);
    }

    return rv;
}