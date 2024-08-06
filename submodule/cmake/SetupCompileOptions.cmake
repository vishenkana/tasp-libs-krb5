set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_BUILD_WITH_INSTALL_RPATH ON)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

add_compile_options(
    -O2
    -pipe
    -fPIC
    -fvisibility=hidden
    -fvisibility-inlines-hidden
    -Wall
    -Wextra
    -Wpedantic

    -Wcast-align
    -Wmissing-declarations
    -Wmissing-format-attribute
    -Wredundant-decls
    -Wvla
    -Wcast-align
    -Wconversion
    -Wdouble-promotion
    -Wfloat-equal
    -Wformat-security
    -Winit-self
    -Wmissing-braces
    -Wmissing-declarations
    -Wmissing-format-attribute
    -Wmissing-include-dirs
    -Wpacked
    -Wpointer-arith
    -Wredundant-decls
    -Wshadow
    -Wsign-conversion
    -Wstrict-overflow
    -Wundef
    -Wunused
    -Wvariadic-macros
    -Wvla
    -Wwrite-strings
)

if("${OS_ID}" STREQUAL "astra" AND "${OS_VERSION_ID}" STREQUAL "1.6")
    add_compile_options(
        -std=c++17
    )
else()
    set(CMAKE_CXX_STANDARD 17)
endif()
