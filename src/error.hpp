#pragma once
#include <iostream>

template <class... Args>
void panic(Args... args) {
    (std::cerr << ... << args) << std::endl;
    exit(-1);
}

template <class... Args>
void warn(Args... args) {
    (std::cerr << ... << args) << std::endl;
}

template <class... Args>
void print(Args... args) {
    (std::cout << ... << args) << std::endl;
}

#ifdef DEBUG
#define ASSERT(expr, message) \
    if(!(expr)) {               \
        panic(message);       \
    }
#else
#define ASSERT(a, b) ;
#endif
