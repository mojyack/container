#include <array>
#include <fstream>
#include <sstream>

#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#include "error.hpp"
#include "fd.hpp"

struct ChildMainArgs {
    const char*          rootfs;
    EventFileDescriptor& ready;
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

auto write_string(const char* const path, const char* const str) -> bool {
    try {
        auto file = std::ofstream(path);
        file << str;
    } catch(const std::exception& e) {
        return false;
    }
    return true;
}

auto parent_write_ug_map(const pid_t child) -> bool {
    {
        auto path = std::stringstream();
        path << "/proc/" << child << "/setgroups";
        if(!write_string(path.str().data(), "deny")) {
            return false;
        }
    }
    {
        auto path = std::stringstream();
        auto data = std::stringstream();
        path << "/proc/" << child << "/gid_map";
        data << "0 " << getgid() << "1\n";
        if(!write_string(path.str().data(), data.str().data())) {
            return false;
        }
    }
    {

        auto path = std::stringstream();
        auto data = std::stringstream();
        path << "/proc/" << child << "/uid_map";
        data << "0 " << getuid() << "1\n";
        if(!write_string(path.str().data(), data.str().data())) {
            return false;
        }
    }
    return true;
}

auto child_main(const ChildMainArgs* const args) -> int {
    args->ready.consume();
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

    auto       ready      = EventFileDescriptor();
    const auto child_args = ChildMainArgs{rootfs, ready};
    const auto child      = clone(reinterpret_cast<CloneEntry>(&child_main), reinterpret_cast<uint8_t*>(stack) + STACK_SIZE, SIGCHLD, const_cast<ChildMainArgs*>(&child_args));
    if(child == -1) {
        return -1;
    }
    if(!parent_write_ug_map(child)) {
        return -1;
    }
    ready.notify();
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
