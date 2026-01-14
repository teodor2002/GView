#pragma once
#include <string>
#include "VirusTotalResult.hpp"

class RESTManager
{
  public:
    static bool QueryVirusTotal(const std::string& apiKey, const std::string& sha256, VirusTotalResult& outResult, std::string& outError);
    static bool UploadFile(const std::string& apiKey, const std::string& filePath, std::string& outError);
};
