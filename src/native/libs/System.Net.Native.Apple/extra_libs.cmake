
macro(append_extra_network_apple_libs NativeLibsExtra)
    find_library(NETWORK_LIBRARY Network)
    find_library(SECURITY_LIBRARY Security)

    list(APPEND ${NativeLibsExtra} ${NETWORK_LIBRARY} ${SECURITY_LIBRARY} -L/usr/lib/swift -lobjc -lswiftCore -lswiftFoundation)
endmacro()
