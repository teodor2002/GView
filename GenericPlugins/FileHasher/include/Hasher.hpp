#pragma once
#include <string>

class Hasher
{
  public:
    static bool ComputeSHA256(const std::string& filePath, std::string& outHash);
};