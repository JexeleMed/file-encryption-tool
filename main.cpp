#include <iostream>
#include <random>
#include <array>
#include <iomanip>
#include <sstream>

// Key generator
std::array<uint8_t, 16> generateKey() {
    std::array<uint8_t, 16> key;
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



int main() {
    auto key = generateKey();
    auto iv = generateKey();
    std::string hexKey = toHex(key);
    std::string hexIV = toHex(iv);
    std::cout << "Hex Key: " << hexKey << std::endl;
    return 0;

}