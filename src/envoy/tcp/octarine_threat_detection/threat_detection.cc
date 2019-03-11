/* Copyright 2018 Istio Authors. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "src/envoy/tcp/octarine_threat_detection/threat_detection.h"

#include "envoy/buffer/buffer.h"
#include "envoy/common/exception.h"
#include "envoy/network/connection.h"
#include "common/common/stack_array.h"

#include "common/common/assert.h"

namespace Envoy {
namespace Tcp {
namespace ThreatDetection {

Config::Config() {
}


Filter::Filter(const ConfigSharedPtr config)
    : config_(config) {
}

void Filter::sendToThreatService(const Network::Connection& connection, Buffer::Instance &data, bool read) {
    ENVOY_CONN_LOG(debug, "ThreatDetection: got data", connection);

    std::string peer_service_id = "static";
    std::string peer_instance_id = "static";
//
//    try {
//        peer_service_id = Utils::getServiceIDFromCert(&connection);
//        peer_instance_id = Utils::getInstanceIDFromCert(&connection);
//    } catch (Utils::NotSLLConnectionException) {
//    } catch (Utils::NoPeerCertificateException) {
//    }

    auto remoteSocket = connection.remoteAddress();
    auto localSocket = connection.localAddress();

    std::string remoteIP = remoteSocket->ip()->addressAsString();
    unsigned short remotePort = remoteSocket->ip()->port();
    std::string localIP = localSocket->ip()->addressAsString();
    unsigned short localPort = localSocket->ip()->port();

    uint64_t num_slices = data.getRawSlices(nullptr, 0);
    STACK_ARRAY(slices, Buffer::RawSlice, num_slices);
    data.getRawSlices(slices.begin(), num_slices);
    for (Buffer::RawSlice &slice : slices) {
        ENVOY_CONN_LOG(debug, "ThreatDetection: sending to service {} bytes.", connection, slice.len_);
        ProcessPacket(const_cast<char *>(remoteIP.c_str()), remotePort, const_cast<char *>(localIP.c_str()),
                      localPort, read ? PACKET_FLOW_TO_SERVER : PACKET_FLOW_TO_CLIENT, slice.mem_, slice.len_,
                      const_cast<char*>(peer_instance_id.c_str()));
    }
}

Network::FilterStatus Filter::onData(Buffer::Instance& data, bool) {
    ENVOY_CONN_LOG(trace, "ThreatDetection: got {} bytes",
                 read_callbacks_->connection(), data.length());

    sendToThreatService(read_callbacks_->connection(), data, true);

    return Network::FilterStatus::Continue;
}

Network::FilterStatus Filter::onWrite(Buffer::Instance& data, bool) {
    ENVOY_CONN_LOG(trace, "ThreatDetection: got {} bytes",
                   read_callbacks_->connection(), data.length());

    sendToThreatService(read_callbacks_->connection(), data, true);

    return Network::FilterStatus::Continue;
}

}  // namespace ThreatDetection
}  // namespace Tcp
}  // namespace Envoy
