#include <iostream>
#include "map"


// require this 'define' for support https
#define CPPHTTPLIB_OPENSSL_SUPPORT

#include "httplib/httplib.h"

#include "Poco/JSON/Parser.h"
#include "Poco/JSON/JSON.h"
#include "Poco/UUIDGenerator.h"
#include "Poco/SHA1Engine.h"
#include "Poco/HMACEngine.h"
#include "Poco/Base64Encoder.h"
#include "Poco/String.h"


#define HELP_INFO "Invalid argument. Demo: \nweb-monitor -u https://www.baidu.com"


std::string get_now_time_str()
{
    auto now = std::chrono::system_clock::now();
    auto ticks = std::chrono::system_clock::to_time_t(now);
    auto local_time = localtime(&ticks);
    std::stringstream time_ss;
    time_ss << std::put_time(local_time, "%F %T");
    return time_ss.str();
}

std::string get_now_time_str_for_sms()
{
    auto now = std::chrono::system_clock::now();
    auto ticks = std::chrono::system_clock::to_time_t(now);
    auto local_time = gmtime(&ticks);
    std::stringstream time_ss;
    time_ss << std::put_time(local_time, "%FT%TZ");
    return time_ss.str();
}


Poco::JSON::Object::Ptr get_config_json(char* _config_path)
{
    std::string cmd_path(_config_path);
    std::stringstream config_path_ss;
    // example: /usr/bin/do -> /usr/bin/
    config_path_ss << cmd_path.substr(0, cmd_path.find_last_of('/') + 1);
    config_path_ss << "config.json";
    auto config_path = config_path_ss.str();
    std::ifstream ifs(config_path, std::ios::in);

    if (!ifs || !ifs.is_open())
    {
        throw std::invalid_argument("config.json not exist");
    }

    Poco::JSON::Parser parser;
    return parser.parse(ifs).extract<Poco::JSON::Object::Ptr>();
}

httplib::Result request_target_host(const char* url, int connection_timeout, int read_timeout)
{
    httplib::Client cli(url);
    // 100 milliseconds
    cli.set_connection_timeout(0, connection_timeout);
    // 2 seconds
    cli.set_read_timeout(0, read_timeout);
    auto res = cli.Get("/", {
                           {"User-Agent", "web-monitor/1.1"}
                       });

    return res;
}

// check http code and content
bool check_result(httplib::Result* http_result, Poco::JSON::Object::Ptr json)
{
    if (!(*http_result))
    {
        std::cout << "Failed to get target url response" << std::endl;
        return false;
    }


    if ((*http_result).error() != httplib::Error::Success)
    {
        std::cout << "Failed to connect target url" << std::endl;
        return false;
    }

    if ((*http_result)->status != 200)
    {
        std::cout << "The target url response code is not equal to 200" << std::endl;
        return false;
    }

    auto hacked_words = json->getArray("HackedWords");

    auto content = (*http_result)->body;
    for (const auto& item : *(hacked_words.get()))
    {
        auto item_str = item.convert<std::string>();
        if (content.find(item_str) != -1)
        {
            std::cout << "find hacked words: " << item_str << ", body: " << content << std::endl;
            return false;
        }
    }
    return true;
}


std::string encode(std::string str)
{
    str = Poco::replace(str, "%3A", "%253A");
    str = Poco::replace(str, "%7E", "~");
    str = Poco::replace(str, "+", "%2B");
    str = Poco::replace(str, ":", "%3A");
    str = Poco::replace(str, "*", "%2A");
    str = Poco::replace(str, "/", "%2F");
    str = Poco::replace(str, "&", "%26");
    str = Poco::replace(str, "=", "%3D");
    return str;
}


std::string sign(const std::string& security_key, const std::string& str)
{
    Poco::HMACEngine<Poco::SHA1Engine> hmac(security_key);
    hmac.update(str);
    auto digest = hmac.digest();
    std::stringstream ss;
    Poco::Base64Encoder encoder(ss);
    for (const auto& item : digest)
    {
        encoder << item;
    }
    encoder.close();
    return ss.str();
}

// Build url and encode key/value
std::string build_url_params(std::map<std::string, std::string>* map)
{
    std::stringstream ss;
    for (const auto& item : *map)
    {
        ss << encode(item.first)
            << "="
            << encode(item.second)
            << "&";
    }
    auto str = ss.str();
    if (str.length() > 0)
    {
        str = str.substr(0, str.length() - 1);
    }
    return str;
}


std::string build_send_sms_url(Poco::JSON::Object::Ptr json)
{
    Poco::UUIDGenerator generator;
    std::map<std::string, std::string> kv;
    // ordered parameters
    kv["AccessKeyId"] = json->get("AccessKeyId").convert<std::string>();
    kv["Action"] = "SendSms";
    kv["Format"] = "Json";
    kv["PhoneNumbers"] = json->get("PhoneNumbers").convert<std::string>();
    kv["RegionId"] = json->get("RegionId").convert<std::string>();
    kv["SignatureMethod"] = "HMAC-SHA1";
    kv["SignatureNonce"] = generator.createOne().toString();
    kv["SignatureVersion"] = "1.0";
    kv["SignName"] = json->get("SignName").convert<std::string>();
    kv["TemplateCode"] = json->get("TemplateCode").convert<std::string>();
    kv["Timestamp"] = get_now_time_str_for_sms();
    kv["Version"] = "2017-05-25";

    auto access_key_secret = json->get("AccessKeySecret").convert<std::string>();
    auto url_params = build_url_params(&kv);
    std::stringstream sign_string_ss;
    sign_string_ss << "GET&%2F&" << encode(url_params);
    std::string sign_value = sign(access_key_secret + "&", sign_string_ss.str());
    // encode again
    kv["Signature"] = encode(sign_value);

    std::stringstream url_ss;
    auto params = "/?" + build_url_params(&kv);
    url_ss << json->get("EndPoint").convert<std::string>() << params;

    return url_ss.str();
}


void check_program_param(int argc, char** argv)
{
    if (argc <= 2 || argc > 3)
    {
        throw std::invalid_argument(HELP_INFO);
    }

    if (argc == 3)
    {
        if (strcmp(argv[1], "-u") != 0)
        {
            throw std::invalid_argument(HELP_INFO);
        }
    }
}

int main(int argc, char** argv)
{
    std::cout << "-----------------------" << std::endl;
    std::cout << get_now_time_str() << ": run web-monitor." << std::endl;

    try
    {
        check_program_param(argc, argv);

        auto json = get_config_json(argv[0]);

        // request target url
        auto result = request_target_host(argv[2],
                                          json->get("ConnectionTimeout"),
                                          json->get("ReadTimeout"));

        // if hacked, then send sms
        if (!check_result(&result, json))
        {
            int notify_type = json->get("NotifyType").convert<int>();

            if (notify_type == 1)
            {
                std::string url = build_send_sms_url(json);
                httplib::Client cli(json->get("EndPoint").convert<std::string>());
                auto res = cli.Get(url);
                if (res->status == 200)
                {
                    std::cout << "send success: " << res->status << std::endl;
                }
                else
                {
                    std::cout << "send fail, code:  " << res->status << ", body: " << res->body << std::endl;
                }
            }
            else if (notify_type == 2)
            {
                auto we_work_key = json->get("WeWorkKey").convert<std::string>();
                httplib::Client cli("https://qyapi.weixin.qq.com");
                auto res = cli.Post("/cgi-bin/webhook/send?key=" + we_work_key,
                                    R"({"msgtype": "text","text": {"content":"目标网站出现异常， 请及时处理"}})",
                                    "application/json; charset=utf-8");
                if (res->status == 200)
                {
                    auto body = res->body;
                    Poco::JSON::Parser parser;
                    auto body_json = parser.parse(body).extract<Poco::JSON::Object::Ptr>();

                    auto errcode = body_json->get("errcode").convert<int>();

                    if (errcode == 0)
                    {
                        std::cout << "send success: " << res->status << std::endl;
                    }
                    else
                    {
                        std::cout << "send fail, body: " << res->body << std::endl;
                    }
                }
                else
                {
                    std::cout << "send fail, code:  " << res->status << ", body: " << res->body << std::endl;
                }
            }
        }
    }
    catch (std::exception& e)
    {
        std::cout << e.what() << std::endl;
    }
    std::cout << "web-monitor end" << std::endl;
    return 0;
}
