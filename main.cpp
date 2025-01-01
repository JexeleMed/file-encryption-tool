#include <iostream>
#include <cmath>
#include <regex>

// FINDING GCD
long long int euclide(long long int a, long long int b) {
    if(a<b)
        std::swap(a, b);
    if(a%b == 0)
        return b;

    return euclide(b,a%b);
}

int main() {

    long int p = 9223372036854775807;
    long int q = 9223372036854775783;

    // int n = p * q;
    std::cout << euclide(p,q);
    // int phi = (p - 1) * (q - 1);
    return 0;

}