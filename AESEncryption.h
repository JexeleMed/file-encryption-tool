#ifndef AES_H
#define AES_H

#include <algorithm>
#include <iostream>
#include <random>
#include <array>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <vector>

using Block = std::array<uint8_t, 16>;
using Blocks = std::vector<Block>;

class AES {
public:
    AES(const std::array<uint8_t, 16>& key, const std::array<uint8_t, 16>& iv);

    void encryptFile(const std::string& inputFilePath, const std::string& outputFilePath);

    std::string getKeyHex() const;
    std::string getIVHex() const;

    void setKey(const std::array<uint8_t, 16>& key);
    void setIV(const std::array<uint8_t, 16>& iv);

private:
    std::array<uint8_t, 16> key;
    std::array<uint8_t, 16> iv;
    std::vector<Block> roundKeys;

    std::vector<Block> keyExpansion(const Block& key);
    void subBytes(Blocks& text);
    void shiftRows(Blocks& blocks);
    void mixColumns(Blocks& blocks);
    uint8_t gfMul(uint8_t a, uint8_t b);
    void addRoundKey(Blocks& blocks, const std::vector<Block>& roundKeys, size_t round);
    Blocks load(const std::string& filename);
    void save(const Blocks& blocks, const std::string& filename);
    std::string toHex(const std::array<uint8_t, 16>& data) const;
    void printBlocks(const Blocks& blocks) const;
};

#endif // AES_H
