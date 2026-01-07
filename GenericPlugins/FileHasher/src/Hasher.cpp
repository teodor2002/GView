#include "Hasher.hpp"
#include <windows.h>
#include <bcrypt.h>
#include <fstream>
#include <vector>
#include <sstream>
#include <iomanip>

#pragma comment(lib, "bcrypt.lib")

bool Hasher::ComputeSHA256(const std::string& filePath, std::string& outHash)
{
    std::ifstream file(filePath, std::ios::binary);
    if (!file)
        return false;

    std::vector<uint8_t> data((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

    BCRYPT_ALG_HANDLE hAlg   = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    DWORD hashObjectSize = 0, cbData = 0;
    DWORD hashSize = 0;

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0))
        return false;

    BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR) &hashObjectSize, sizeof(DWORD), &cbData, 0);
    BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PUCHAR) &hashSize, sizeof(DWORD), &cbData, 0);

    std::vector<uint8_t> hashObject(hashObjectSize);
    std::vector<uint8_t> hash(hashSize);

    if (BCryptCreateHash(hAlg, &hHash, hashObject.data(), hashObjectSize, nullptr, 0, 0))
        return false;

    BCryptHashData(hHash, data.data(), (ULONG) data.size(), 0);
    BCryptFinishHash(hHash, hash.data(), hashSize, 0);

    std::ostringstream oss;
    for (auto b : hash)
        oss << std::hex << std::setw(2) << std::setfill('0') << (int) b;

    outHash = oss.str();

    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    return true;
}
