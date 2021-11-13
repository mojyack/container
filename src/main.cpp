#include <filesystem>

#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#include "error.hpp"

struct ChildMainArgs {
    const char* rootfs;
};

using CloneEntry = int (*)(void*);

auto chroot_dir(const char* const path) {
    if(chroot(path) != 0) {
        return -1;
    }
    if(chdir("/") != 0) {
        return -1;
    }
    return 0;
}

auto child_main(const ChildMainArgs* const args) -> int {
    if(chroot_dir(args->rootfs) == -1) {
        return -1;
    }
    constexpr auto INIT_PATH = "/bin/init";
    constexpr auto STR_NULL  = (char*)(NULL);
    const auto     init_arg  = std::array<char*, 2>{const_cast<char*>(INIT_PATH), STR_NULL};
    const auto     init_env  = std::array<char*, 1>{STR_NULL};
    execve(INIT_PATH, init_arg.data(), init_env.data());
    return -1;
}

auto start_child(const char* const rootfs) -> int {
    constexpr auto STACK_SIZE = 16 * 1024 * 1024;
    const auto     stack      = mmap(NULL, STACK_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_GROWSDOWN | MAP_STACK, -1, 0);
    if(stack == MAP_FAILED) {
        return -1;
    }

    const auto child_args = ChildMainArgs{rootfs};
    const auto child      = clone(reinterpret_cast<CloneEntry>(&child_main), reinterpret_cast<uint8_t*>(stack) + STACK_SIZE, SIGCHLD, const_cast<ChildMainArgs*>(&child_args));
    if(child == -1) {
        return -1;
    }
    if(waitpid(child, NULL, 0) == -1) {
        return -1;
    }
    return 0;
}

auto main(const int argc, const char* const argv[]) -> int {
    constexpr const char* HELP = "Usage: container ROOTFS";
    ASSERT(argc == 2, HELP)

    return start_child(argv[1]);
}
