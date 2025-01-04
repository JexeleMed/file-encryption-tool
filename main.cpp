#include <iostream>
#include <random>
#include <array>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <vector>

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
void load(const std::string& name, std::array<uint8_t, 16> key, std::array<uint8_t, 16> iv) {
    std::ifstream file(name, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Failed to open the file: " << name << std::endl;
        return;
    }

    constexpr  size_t chunkSize = 16;
    std::vector<char> buffer(chunkSize);
    size_t chunkIndex = 0;
    while (file.read(buffer.data(), chunkSize) || file.gcount() > 0) {
        size_t bytesRead = file.gcount();
        std::cout << "Chunk " << chunkIndex++ << " bytes read: " << bytesRead << std::endl;
        for(size_t i = 0; i < bytesRead; ++i) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (0xff & buffer[i]) << " ";
        }
        std::cout << std::endl;

        if (bytesRead < chunkSize) {
            size_t paddingLength = chunkSize - bytesRead;
            std::cout << "Padding applied: " << paddingLength << " bytes" << std::endl;

            for(size_t i = bytesRead; i < chunkSize; ++i) {
                buffer[i] = static_cast<char>(paddingLength);
            }
            // std::cout << "Padded chunk: ";
            for(size_t i = 0; i < chunkSize; ++i) {
                std::cout <<  std::hex << std::setw(2) << std::setfill('0') << (0xff & buffer[i]) << " ";
            }
            std::cout << std::endl;
        }

    }
    // End of loading
    for(int j = 0; j < buffer.size(); j++) {
        buffer[j] ^= iv[j];
        std::cout << buffer[j] << std::endl;
    }
    file.close();
}


int main() {
    auto key = generateKey();
    auto iv = generateKey();
    std::string hexKey = toHex(key);
    std::string hexIV = toHex(iv);
    std::cout << "Hex Key: " << hexKey << std::endl;
    std::cout << "Hex IV: " << hexIV << std::endl;

    std::string path = "sample.txt";
    load(path, key, iv);
    return 0;

}