cmake_minimum_required(VERSION 3.12)
project(crypto-engine C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Configure liboqs options before adding its directory
set(OQS_USE_OPENSSL OFF CACHE BOOL "Build liboqs without OpenSSL" FORCE)
set(OQS_BUILD_SHARED_LIBS OFF CACHE BOOL "Build liboqs as static library" FORCE)

# Build liboqs submodule inline
add_subdirectory(liboqs)

# Main build target for Day 4 Keypair Generator
add_executable(kyber_keypair src/kyber_keypair.c)
target_link_libraries(kyber_keypair PRIVATE oqs)
target_include_directories(kyber_keypair PRIVATE liboqs/src/common)

# Main build target for Day 5 Encrypt/Decrypt Round-Trip
add_executable(kyber_roundtrip src/kyber_roundtrip.c)
target_link_libraries(kyber_roundtrip PRIVATE oqs)
target_include_directories(kyber_roundtrip PRIVATE liboqs/src/common)

