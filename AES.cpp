#include "AES.h"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <algorithm>
#include <random>


const std::array<uint8_t, 256> AES::sbox = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, /* ... */ 0x16
};

const std::array<uint8_t, 10> AES::rcon = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
};

// Constructor
AES::AES(const std::array<uint8_t, 16>& key, const std::array<uint8_t, 16>& iv)
    : key(key), iv(iv) {
    roundKeys = keyExpansion(key);
}

// Key Expansion
std::vector<Block> AES::keyExpansion(const Block& key) {
    std::vector<Block> roundKeys(11);
    roundKeys[0] = key;

    uint32_t rconIndex = 0;
    for (size_t round = 1; round <= 10; ++round) {
        std::array<uint8_t, 4> temp = {
            roundKeys[round - 1][12],
            roundKeys[round - 1][13],
            roundKeys[round - 1][14],
            roundKeys[round - 1][15],
        };

        std::rotate(temp.begin(), temp.begin() + 1, temp.end());

        for (auto& byte : temp) {
            byte = sbox[byte];
        }

        temp[0] ^= rcon[rconIndex++];

        for (size_t i = 0; i < 4; ++i) {
            roundKeys[round][i] = roundKeys[round - 1][i] ^ temp[i];
        }

        for (size_t i = 4; i < 16; ++i) {
            roundKeys[round][i] = roundKeys[round - 1][i] ^ roundKeys[round][i - 4];
        }
    }

    return roundKeys;
}

// SubBytes
void AES::subBytes(Blocks& blocks) {
    for (auto& block : blocks) {
        for (auto& byte : block) {
            byte = sbox[byte];
        }
    }
}

// ShiftRows Helper
void AES::shiftRows(Blocks& blocks) {
    for (auto& block : blocks) {
        std::rotate(block.begin() + 4, block.begin() + 5, block.begin() + 8);
        std::rotate(block.begin() + 8, block.begin() + 10, block.begin() + 12);
        std::rotate(block.begin() + 12, block.begin() + 15, block.begin() + 16);
    }
}

// gfMul
uint8_t AES::gfMul(uint8_t a, uint8_t b) {
    uint8_t res = 0;
    while (b) {
        if (b & 1) res ^= a;
        bool carry = a & 0x80;
        a <<= 1;
        if (carry) a ^= 0x1B;
        b >>= 1;
    }
    return res;
}

// MixColumns Helper
void AES::mixColumns(Blocks& blocks) {
    for (auto& block : blocks) {
        for (int col = 0; col < 4; ++col) {
            uint8_t b0 = block[col];
            uint8_t b1 = block[col + 4];
            uint8_t b2 = block[col + 8];
            uint8_t b3 = block[col + 12];

            block[col]      = gfMul(0x02, b0) ^ gfMul(0x03, b1) ^ b2 ^ b3;
            block[col + 4]  = b0 ^ gfMul(0x02, b1) ^ gfMul(0x03, b2) ^ b3;
            block[col + 8]  = b0 ^ b1 ^ gfMul(0x02, b2) ^ gfMul(0x03, b3);
            block[col + 12] = gfMul(0x03, b0) ^ b1 ^ b2 ^ gfMul(0x02, b3);
        }
    }
}


void AES::addRoundKey(Blocks& blocks, const std::vector<Block>& roundKeys, size_t round) {
    for (auto& block : blocks) {
        for (size_t i = 0; i < block.size(); ++i) {
            block[i] ^= roundKeys[round][i];
        }
    }
}


Blocks AES::load(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Failed to open file: " << filename << std::endl;
        return {};
    }

    Blocks blocks;
    while (!file.eof()) {
        constexpr size_t chunkSize = 16;
        Block block = {};
        file.read(reinterpret_cast<char*>(block.data()), chunkSize);
        size_t bytesRead = file.gcount();


        if (bytesRead < chunkSize) {
            std::fill(block.begin() + bytesRead, block.end(), static_cast<uint8_t>(chunkSize - bytesRead));
        }

        blocks.push_back(block);
    }

    return blocks;
}


void AES::save(const Blocks& blocks, const std::string& filename) {
    std::ofstream file(filename, std::ios::binary);
    if (!file) {
        std::cerr << "Failed to open file for writing: " << filename << std::endl;
        return;
    }

    for (const auto& block : blocks) {
        file.write(reinterpret_cast<const char*>(block.data()), block.size());
    }
}


std::string AES::toHex(const std::array<uint8_t, 16>& data) const {
    std::ostringstream oss;
    for (uint8_t byte : data) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    return oss.str();
}


void AES::encryptFile(const std::string& inputFilePath, const std::string& outputFilePath) {
    Blocks data = load(inputFilePath);
    addRoundKey(data, roundKeys, 0);

    for (size_t round = 1; round < 10; ++round) {
        subBytes(data);
        shiftRows(data);
        mixColumns(data);
        addRoundKey(data, roundKeys, round);
    }

    save(data, outputFilePath);
}

void AES::invMixColumns(Blocks& blocks) {
    for (auto& block : blocks) {
        for (int col = 0; col < 4; ++col) {
            uint8_t b0 = block[col];
            uint8_t b1 = block[col + 4];
            uint8_t b2 = block[col + 8];
            uint8_t b3 = block[col + 12];

            block[col]      = gfMul(0x0e, b0) ^ gfMul(0x0b, b1) ^ gfMul(0x0d, b2) ^ gfMul(0x09, b3);
            block[col + 4]  = gfMul(0x09, b0) ^ gfMul(0x0e, b1) ^ gfMul(0x0b, b2) ^ gfMul(0x0d, b3);
            block[col + 8]  = gfMul(0x0d, b0) ^ gfMul(0x09, b1) ^ gfMul(0x0e, b2) ^ gfMul(0x0b, b3);
            block[col + 12] = gfMul(0x0b, b0) ^ gfMul(0x0d, b1) ^ gfMul(0x09, b2) ^ gfMul(0x0e, b3);
        }
    }
}


void AES::decryptFile(const std::string& inputFilePath, const std::string& outputFilePath) {
    Blocks data = load(inputFilePath);
    addRoundKey(data, roundKeys, 0);

    for (size_t round = 1; round < 10; ++round) {
        addRoundKey(data, roundKeys, round);
        invMixColumns(data);
    }

    save(data, outputFilePath);

}