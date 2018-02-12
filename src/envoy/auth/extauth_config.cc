#include "extauth_config.h"

#include "extauth.h"

#include "envoy/registry/registry.h"
//#include "envoy/server/filter_config.h"


namespace Envoy {
namespace Server {
namespace Configuration {

const std::string EXTAUTH_HTTP_FILTER_SCHEMA(R"EOF(
  {
    "$schema": "http://json-schema.org/schema#",
    "type" : "object",
    "properties" : {
      "cluster" : {"type" : "string"},
      "timeout_ms": {"type" : "integer"}
    },
    "required" : ["cluster", "timeout_ms"],
    "additionalProperties" : false
  }
  )EOF");

HttpFilterFactoryCb ExtAuthConfig::createFilterFactory(const Json::Object& json_config,
                                                       const std::string& stats_prefix,
                                                       FactoryContext& context) {

//class ExtAuthConfig: public NamedHttpFilterConfigFactory {
//  public:
//   HttpFilterFactoryCb CreateFilterFactory(const Json::Object& json_config,
//                                           const std::string& stats_prefix,
//                                           FactoryContext& context) override {
 
  json_config.validateSchema(EXTAUTH_HTTP_FILTER_SCHEMA);

  Http::ExtAuthConfigConstSharedPtr config(new Http::ExtAuthConfig{
      context.clusterManager(), Http::ExtAuth::generateStats(stats_prefix, context.scope()),
      json_config.getString("cluster"),
      std::chrono::milliseconds(json_config.getInteger("timeout_ms"))});
  return [config](Http::FilterChainFactoryCallbacks& callbacks) -> void {
    callbacks.addStreamDecoderFilter(Http::StreamDecoderFilterSharedPtr{new Http::ExtAuth(config)}); };


}


/**
 * Static registration for the extauth filter. @see RegisterHttpFilterConfigFactory.
 */
  //static RegisterHttpFilterConfigFactory<ExtAuthConfig> register_; 
  static Registry::RegisterFactory<ExtAuthConfig, NamedHttpFilterConfigFactory> registered_;


} // Configuration
} // Server
} // Envoy
