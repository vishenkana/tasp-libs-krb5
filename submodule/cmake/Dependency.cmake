find_package(PkgConfig REQUIRED)

function(tasp_check_modules prefix)
    string(TOUPPER ${prefix} upper_prefix)

    pkg_check_modules(${upper_prefix} ${prefix})
    if(NOT DEFINED ${upper_prefix}_LDFLAGS)
        set(${upper_prefix}_LDFLAGS ${prefix} PARENT_SCOPE)
    endif()
endfunction(tasp_check_modules)
