install(DIRECTORY include/tasp
    DESTINATION /usr/include
)

set(CMAKE_INSTALL_PREFIX /usr)
install(TARGETS ${PROJECT_NAME}
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION /lib/x86_64-linux-gnu
)
