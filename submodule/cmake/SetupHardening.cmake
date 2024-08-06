add_compile_options(
    -fstack-protector-strong
    -Wformat
    -Wformat-security
    -Werror=format-security
    -fno-strict-aliasing
    -fno-delete-null-pointer-checks
    -Wp,-D_FORTIFY_SOURCE=2
    -Wdate-time
    -flto
)

macro(add_linker_flags flag)
    string(APPEND CMAKE_SHARED_LINKER_FLAGS " ${flag}")
    string(APPEND CMAKE_EXE_LINKER_FLAGS " ${flag}")
endmacro(add_linker_flags)

add_linker_flags("-Wl,--allow-shlib-undefined")
add_linker_flags("-Wl,--as-needed")
add_linker_flags("-Wl,-z,noexecstack")
add_linker_flags("-Wl,-z,relro,-z,now")
add_linker_flags("-fuse-ld=gold -flto")

string(APPEND CMAKE_EXE_LINKER_FLAGS " -pie")
