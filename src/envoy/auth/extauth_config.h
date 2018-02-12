#pragma once

#include <string>

//#include "envoy/server/instance.h"

//#include "server/config/network/http_connection_manager.h"

//#include "src/envoy/auth/http_filter.h"
//#include "envoy/registry/registry.h"
//#include "google/protobuf/util/json_util.h"
//#include "src/envoy/auth/auth_store.h"
//#include "src/envoy/auth/config.pb.validate.h"

#include "envoy/server/filter_config.h"
#include "common/config/well_known_names.h"
#include "common/protobuf/protobuf.h"

namespace Envoy {
namespace Server {
namespace Configuration {

/**
 * Config registration for the ExtAuth filter. @see HttpFilterConfigFactory.
 */
class ExtAuthConfig : public NamedHttpFilterConfigFactory {
 public:
  HttpFilterFactoryCb createFilterFactory(const Json::Object& config,
                                          const std::string& stats_prefix,
                                          FactoryContext& context) override;


  std::string name() override { return "extauth"; }
};


} // Configuration
} // Server
} // Envoy
