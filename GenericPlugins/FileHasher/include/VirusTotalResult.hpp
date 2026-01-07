#pragma once
#include <string>

struct VirusTotalResult {
    bool found          = false;
    uint32_t malicious  = 0;
    uint32_t suspicious = 0;
    uint32_t harmless   = 0;
    uint32_t undetected = 0;
    std::string permalink;
};
