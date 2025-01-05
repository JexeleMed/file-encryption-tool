#include <iostream>
#include <random>
#include <array>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <vector>


using Block = std::array<uint8_t, 16>;
using Blocks = std::vector<Block>;

// Key generator
std::array<uint8_t, 16> generateKey() {
    std::array<uint8_t, 16> key = {};
    std::random_device rd;

    for(auto& byte : key) {
        byte = rd() % 256;
    }

    return key;
}


// BYTES to HEX
template <std::size_t N>
std::string toHex(const std::array<uint8_t, N>& key) {
    std::ostringstream oss;
    for (uint8_t byte : key) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    return oss.str();
}

// Load file to buffer and apply padding
Blocks load(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Failed to open file: " << filename << std::endl;
        return {};
    }

    Blocks blocks;
    constexpr size_t chunkSize = 16;

        while (!file.eof()) {
            Block block = {};
            file.read(reinterpret_cast<char*>(block.data()), chunkSize);
            size_t bytesRead = file.gcount();

            // Padding
            if (bytesRead < chunkSize) {
                std::fill(block.begin() + bytesRead, block.end(), static_cast<uint8_t>(chunkSize - bytesRead));
            }

            blocks.push_back(block);
        }

    return blocks;
}


// Plain text XORing with RoundKey
void addRoundKey(std::array<uint8_t, 16>& state , const std::array<uint8_t, 16>& roundKey) {
    for (size_t i = 0; i < state.size(); ++i) {
        state[i] ^= roundKey[i];
    }
}

int main() {
    auto key = generateKey();
    auto iv = generateKey();
    std::string hexKey = toHex(key);
    std::string hexIV = toHex(iv);
    std::cout << "Hex Key: " << hexKey << std::endl;
    std::cout << "Hex IV: " << hexIV << std::endl;

    std::string path = "sample.txt";
    Blocks data = load(path);

    for (size_t i = 0; i < data.size(); ++i) {
        std::cout << "Block " << i << ": ";
        for (uint8_t byte : data[i]) {
            std::cout << std::hex << static_cast<int>(byte) << " ";
        }
        std::cout << std::endl;
    }
    return 0;

}