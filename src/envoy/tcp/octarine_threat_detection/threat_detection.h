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

#pragma once

#include "envoy/network/filter.h"

#include "common/common/logger.h"

// TODO: Needs to be manually copied from exported threatservice header when changed.
extern "C" void ProcessPacket(char* p0, short unsigned int p1, char* p2, short unsigned int p3, unsigned int p4, void* p5, int p6, char* p7, char* p8);

enum PACKET_FLOW {
    PACKET_FLOW_UNDEFINED = 0,
    PACKET_FLOW_TO_SERVER = 1,
    PACKET_FLOW_TO_CLIENT = 2,
};

namespace Envoy {
namespace Tcp {
namespace ThreatDetection {

/**
 * Global configuration for Threat Detection.
 */
class Config {
 public:
  Config();
};

typedef std::shared_ptr<Config> ConfigSharedPtr;

class Filter : public Network::Filter,
               Logger::Loggable<Logger::Id::filter> {
 public:
  Filter(const ConfigSharedPtr config);

  // Network::ReadFilter
  Network::FilterStatus onData(Buffer::Instance& data,
                               bool end_stream) override;
  Network::FilterStatus onNewConnection() override {
    return Network::FilterStatus::Continue;
  }
  void initializeReadFilterCallbacks(
      Network::ReadFilterCallbacks& callbacks) override {
    read_callbacks_ = &callbacks;
  }

  // Network::WriteFilter
  Network::FilterStatus onWrite(Buffer::Instance& data, bool end_stream) override;

 private:
  void sendToThreatService(const Network::Connection& connection, Buffer::Instance &data, bool read);

  ConfigSharedPtr config_;
  Network::ReadFilterCallbacks* read_callbacks_{};
};

}  // namespace ThreatDetection
}  // namespace Tcp
}  // namespace Envoy
