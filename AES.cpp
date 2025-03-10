#include "AES.h"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <algorithm>
#include <random>


const std::array<uint8_t, 256> AES::sbox = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa8, 0x51, 0xa3,
    0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6,
    0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c,
    0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7,
    0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81,
    0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee,
    0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32,
    0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3,
    0xac, 0x62, 0x91, 0x95, 0x0f, 0x3f, 0x02, 0x7f,
    0x05, 0x08, 0x16, 0x6a, 0x4b, 0x21, 0x34, 0xe2,
    0x8c, 0x55, 0x74, 0x09, 0x47, 0x91, 0xf4, 0x39
};
const std::array<uint8_t, 256> AES::invsbox = {
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38,
        0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01,
        0x67, 0x2b, 0xfe, 0xd7, 0x76, 0x76, 0xd3, 0x87,
        0x50, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0x0c, 0x11,
        0x64, 0x99, 0x4f, 0x40, 0x09, 0x8b, 0x7e, 0xd2,
        0x6e, 0x8c, 0x41, 0x2c, 0xa7, 0x7d, 0xb3, 0x1d,
        0xb1, 0x45, 0x69, 0xc1, 0x30, 0x3a, 0x0e, 0xa0,
        0x7f, 0x43, 0x44, 0x13, 0x88, 0x34, 0x77, 0x91,
        0x11, 0x30, 0x73, 0x93, 0x58, 0x44, 0x99, 0x69,
        0x59, 0xa3, 0x9f, 0x64, 0x9e, 0xd9, 0x10, 0x40,
        0x92, 0xa4, 0xe5, 0x34, 0xf9, 0x30, 0x24, 0xd3,
        0x4d, 0xb9, 0x82, 0x4e, 0x0a, 0x8a, 0x83, 0x76,
        0x77, 0x7b, 0x4e, 0x81, 0x43, 0x4a, 0x61, 0x2f,
        0x5a, 0x30, 0x6b, 0x66, 0x29, 0x59, 0xd0, 0x62,
        0x4d, 0x23, 0x11, 0x10, 0x77, 0xe9, 0x80, 0x33,
        0x60, 0x9a, 0x51, 0x0d, 0x37, 0x69, 0x55, 0x25,
        0x8b, 0xb1, 0x5c, 0x74, 0x57, 0x57, 0x9b, 0x8d,
        0x8e, 0x28, 0x30, 0x59, 0x80, 0x99, 0x92, 0x72,
        0x8e, 0x8b, 0xf5, 0x72, 0x27, 0x90, 0x6b, 0x4f,
        0x4f, 0x8b, 0x33, 0xa0, 0xf1, 0x93, 0xa0, 0x27,
        0x28, 0x66, 0x37, 0x7b, 0x22, 0x24, 0x70, 0x6d,
        0x72, 0xb4, 0x60, 0x5b, 0xc5, 0x38, 0x81, 0x98,
        0x94, 0x74, 0xb1, 0x31, 0xb8, 0x4b, 0xb1, 0x81,
        0x44, 0x67, 0x36, 0xa3, 0x5d, 0x56, 0xd1, 0x8b
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
void AES::invsubBytes(Blocks& blocks) {
    for (auto& block : blocks) {
        for (auto& byte : block) {
            byte = invsbox[byte];
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

#include <fstream>
#include <iostream>
#include <cctype>  // For isprint()

void AES::saveTxt(const Blocks& blocks, const std::string& filename) {
    std::ofstream file(filename);
    if (!file) {
        std::cerr << "Failed to open file for writing: " << filename << std::endl;
        return;
    }

    for (const auto& block : blocks) {
        for (const auto& byte : block) {
            // If the byte is a printable ASCII character, write it as a character
            if (std::isprint(byte)) {
                file << static_cast<char>(byte);
            } else {
                // If the byte is not printable, replace it with a placeholder (e.g., dot or space)
                file << '.';
            }
        }
        file << std::endl;  // New line after each block
    }

    std::cout << "Successfully saved data to " << filename << std::endl;
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

    for (size_t round = 9; round > 0; --round) {
        addRoundKey(data, roundKeys, round);
        invMixColumns(data);
        shiftRows(data);
        invsubBytes(data);
    }

    saveTxt(data, outputFilePath);

}