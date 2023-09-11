project(9PFuseLib)
add_library(lib STATIC auth_getkey.c auth_proxy.c auth_rpc.c convD2M.c convM2D.c convM2S.c convS2M.c read9pmsg.c readn.c strecpy.c)

target_include_directories(lib PUBLIC ../include)
