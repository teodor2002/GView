#include "RESTManager.hpp"
#include <curl/curl.h>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

static size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp)
{
    reinterpret_cast<std::string*>(userp)->append(reinterpret_cast<char*>(contents), size * nmemb);
    return size * nmemb;
}

bool RESTManager::QueryVirusTotal(const std::string& apiKey, const std::string& sha256, VirusTotalResult& outResult, std::string& outError)
{
    outResult = {};
    outError.clear();

    CURL* curl = curl_easy_init();
    if (!curl) {
        outError = "Failed to initialize CURL";
        return false;
    }

    std::string response;
    std::string url = "https://www.virustotal.com/api/v3/files/" + sha256;

    struct curl_slist* headers = nullptr;
    headers                    = curl_slist_append(headers, ("x-apikey: " + apiKey).c_str());

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "GView-FileHasher");

    CURLcode res = curl_easy_perform(curl);

    long httpCode = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        outError = "CURL error";
        return false;
    }

    if (httpCode == 404) {
        outResult.found = false;
        return true;
    }

    if (httpCode != 200) {
        outError = "HTTP error: " + std::to_string(httpCode);
        return false;
    }

    try {
        auto j = json::parse(response);

        auto stats = j["data"]["attributes"]["last_analysis_stats"];

        outResult.found      = true;
        outResult.malicious  = stats.value("malicious", 0);
        outResult.suspicious = stats.value("suspicious", 0);
        outResult.harmless   = stats.value("harmless", 0);
        outResult.undetected = stats.value("undetected", 0);
        outResult.permalink  = j["data"]["links"].value("self", "");
    } catch (const std::exception& e) {
        outError = std::string("JSON parse error: ") + e.what();
        return false;
    }

    return true;
}

bool RESTManager::UploadFile(const std::string& apiKey, const std::string& filePath, std::string& outError)
{
    outError.clear();
    CURL* curl = curl_easy_init();
    if (!curl) {
        outError = "Failed to init CURL";
        return false;
    }

    // 1. Prepare the Multipart form (The File)
    curl_mime* mime     = curl_mime_init(curl);
    curl_mimepart* part = curl_mime_addpart(mime);

    // Field name must be "file"
    curl_mime_name(part, "file");
    curl_mime_filedata(part, filePath.c_str());

    // 2. Set Headers
    struct curl_slist* headers = nullptr;
    headers                    = curl_slist_append(headers, ("x-apikey: " + apiKey).c_str());

    // 3. Configure CURL
    std::string response;
    curl_easy_setopt(curl, CURLOPT_URL, "https://www.virustotal.com/api/v3/files");
    curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime); // Attach the file
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "GView-FileHasher");

    // 4. Perform Request
    CURLcode res  = curl_easy_perform(curl);
    long httpCode = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);

    // Cleanup
    curl_slist_free_all(headers);
    curl_mime_free(mime);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        outError = "CURL Error: " + std::string(curl_easy_strerror(res));
        return false;
    }

    // VT returns 200 OK with the analysis ID if upload is successful
    if (httpCode == 200) {
        return true;
    } else {
        outError = "Upload failed. HTTP " + std::to_string(httpCode);
        return false;
    }
}