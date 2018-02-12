#include <map>
#include <string>
#include <vector>
#include <sstream>
#include <iostream>
#include <stdio.h>

#include "extauth.h"

#include "common/common/assert.h"
#include "common/common/enum_to_int.h"
#include "common/http/message_impl.h"
#include "common/http/utility.h"
#include "common/http/header_map_impl.h"


namespace Envoy {
namespace Http {

static LowerCaseString header_to_add(std::string("x-ark3-stuff"));

ExtAuth::ExtAuth(ExtAuthConfigConstSharedPtr config) : config_(config) {}

ExtAuth::~ExtAuth() { ASSERT(!auth_request_); }

FilterHeadersStatus ExtAuth::decodeHeaders(HeaderMap& headers, bool) {
  //log().info("ExtAuth Request received; contacting auth server");
  ENVOY_LOG(info, "ExtAuth Request received; contacting auth server");
  // Copy original headers as a JSON object
  std::string json("{");
  headers.iterate(
      [](const HeaderEntry& header, void* ctx) -> HeaderMap::Iterate {
        std::string* jsonPtr = static_cast<std::string*>(ctx);
        std::string key(header.key().c_str());
        std::string value(header.value().c_str());
        std::map<std::string, std::string>  request_body_map;

        // TODO(ark3): Ensure that key and value are sane so generated JSON is valid
        *jsonPtr += "\n \"" + key + "\"= \"" + value + "\"";
      
        return HeaderMap::Iterate::Continue;
      },
      &json);
  std::string request_body = json.substr(0, json.size() - 1) + "\n}"; // Drop trailing comma
  //std::map< std::string, std::map<std::string, std::string> > request_body_map;
  //request_body_map["input"]["method"] = "GET"; 


  // convert string to a map
  std::map<std::string, std::string> m;
  std::string m_key, m_val;
  std::istringstream iss(request_body);
  while(std::getline(std::getline(iss, m_key, '=') >> std::ws, m_val))
        m[m_key] = m_val;

  //log().info("Request Received");
  ENVOY_LOG(info, "Request Received");
  for(auto const& p: m) {
        //log().info("Key{},Value {}", p.first, p.second);
        ENVOY_LOG(info, "Key{},Value {}", p.first, p.second);
  }

  //log().info("XXXXX {}", headers.Host()->value().c_str());
  //log().info("XXXXX {}", headers.Path()->value().c_str());
  //log().info("XXXXX {}", headers.Method()->value().c_str());


  // get method and path
  std::string method, path, auth;
  method = m[" \":method\""];
  path = m[" \":path\""];
  auth = m[" \"authorization\""];

  // Get the encoded user info from the auth value
  std::string str(auth);
  std::string buf;
  std::stringstream ss(str);

  std::vector<std::string> tokens;

  while (ss >> buf)
    tokens.push_back(buf);

  std::string userinfo("\"");
  userinfo += tokens[1];

  char buff[100];
  snprintf(buff, sizeof(buff), "{\"input\":{\"method\":%s, \"path\": %s, \"auth\":%s}}", method.c_str(), path.c_str(), userinfo.c_str());
  std::string request_body_opa = buff;

  //std::string request_body_opa = "{\"input\":{\"method\":\"GET\"}}"; // Drop trailing comma
  //log().info("Request To OPA {}", request_body_opa);
  ENVOY_LOG(info, "Request To OPA {}", request_body_opa);

//  Json::Value req;
//  req["method"] = "GET";

//  Json::Value req_body;
//  req_body["input"] = req;

//  Json::StyledWriter writer;
//  const string request_body = writer.write(req);

  // Request external authentication
  auth_complete_ = false;
  MessagePtr request(new RequestMessageImpl());
  request->headers().insertMethod().value(Http::Headers::get().MethodValues.Post);
  request->headers().insertPath().value(std::string("/v1/data/httpapi/authz"));
  //request->headers().insertPath().value(std::string("/ambassador/auth"));
  request->headers().insertHost().value(config_->cluster_); // cluster name is Host: header value!
  request->headers().insertContentType().value(std::string("application/json"));
  request->headers().insertContentLength().value(request_body_opa.size());
  request->body() = Buffer::InstancePtr(new Buffer::OwnedImpl(request_body_opa));
  auth_request_ =
      config_->cm_.httpAsyncClientForCluster(config_->cluster_)
          .send(std::move(request), *this, Optional<std::chrono::milliseconds>(config_->timeout_));
  // .send(...) -> onSuccess(...) or onFailure(...)
  // This handle can be used to ->cancel() the request.

  // Stop until we have a result
  return FilterHeadersStatus::StopIteration;
}

FilterDataStatus ExtAuth::decodeData(Buffer::Instance&, bool) {
  if (auth_complete_) {
    return FilterDataStatus::Continue;
  }
  return FilterDataStatus::StopIterationAndBuffer;
}

FilterTrailersStatus ExtAuth::decodeTrailers(HeaderMap&) {
  if (auth_complete_) {
    return FilterTrailersStatus::Continue;
  }
  return FilterTrailersStatus::StopIteration;
}

//ExtAuthStats ExtAuth::generateStats(const std::string& prefix, Stats::Store& store) {
ExtAuthStats ExtAuth::generateStats(const std::string& prefix, Stats::Scope& scope) {
  std::string final_prefix = prefix + "extauth.";
  return {ALL_EXTAUTH_STATS(POOL_COUNTER_PREFIX(scope, final_prefix))};
}

void ExtAuth::onSuccess(Http::MessagePtr&& response) {
  auth_request_ = nullptr;
  uint64_t response_code = Http::Utility::getResponseStatus(response->headers());
  std::string response_body(response->bodyAsString());
  //log().info("OPA responded with code {}", response_code);
  ENVOY_LOG(info, "OPA responded with code {}", response_code);
  if (!response_body.empty()) {
    //log().info("OPA said: {}", response->bodyAsString());
    ENVOY_LOG(info, "OPA said: {}", response->bodyAsString());
  }

  // check OPA result
  std::size_t found = response_body.find("true");
  if (found == std::string::npos) {
  //if (response_code != enumToInt(Http::Code::OK)) {
    //log().info("OPA rejecting request");
    ENVOY_LOG(info, "OPA rejecting request");
    config_->stats_.rq_rejected_.inc();
    response->headers().insertStatus().value(403);
    Http::HeaderMapPtr response_headers{new HeaderMapImpl(response->headers())};     
    callbacks_->encodeHeaders(std::move(response_headers), response_body.empty());
    if (!response_body.empty()) {
      Buffer::OwnedImpl buffer(response_body);
      callbacks_->encodeData(buffer, true);
    }
    return;
  }

  //log().info("OPA accepting request");
  ENVOY_LOG(info, "OPA accepting request");
  config_->stats_.rq_passed_.inc();
  auth_complete_ = true;
  callbacks_->continueDecoding();
}

void ExtAuth::onFailure(Http::AsyncClient::FailureReason) {
  auth_request_ = nullptr;
  //log().warn("ExtAuth Auth request failed");
  ENVOY_LOG(warn, "ExtAuth Auth request failed");
  config_->stats_.rq_failed_.inc();
  Http::Utility::sendLocalReply(*callbacks_, true, Http::Code::ServiceUnavailable,
                                std::string("Auth request failed."));
}

void ExtAuth::onDestroy() {
  if (auth_request_) {
    auth_request_->cancel();
    auth_request_ = nullptr;
  }
}

void ExtAuth::setDecoderFilterCallbacks(StreamDecoderFilterCallbacks& callbacks) {
  callbacks_ = &callbacks;
}

} // Http
} // Envoy
