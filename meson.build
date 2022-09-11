project ('libcommunist', 'cpp', default_options : ['cpp_std=c++17'])
incdir = include_directories('include')
src = ['src/AuxFuncNet.cpp', 'src/DHTOperations.cpp', 'src/FileReceiveOp.cpp', 'src/FileSending.cpp', 'src/LibCommunist.cpp', 'src/LocalNetworkOp.cpp', 'src/MsgProfileReceive.cpp', 'src/MsgSending.cpp', 'src/NetOperationsComm.cpp', 'src/NetworkOperations.cpp', 'src/OutAuxFunc.cpp', 'src/RelayOperations.cpp']
zip = dependency ('libzip', method : 'pkg-config')
gcrypt = dependency ('libgcrypt', method : 'pkg-config')
libtorrent = dependency ('libtorrent-rasterbar', method : 'pkg-config')
thread_dep = dependency ('threads')
pkg = import ('pkgconfig')
if host_machine.system() == 'windows'
	add_global_arguments ('-U_FILE_OFFSET_BITS', language : 'cpp')
endif 
lib = library('communist', sources : src, include_directories : incdir, dependencies : [zip, gcrypt, libtorrent, thread_dep], version : '1.0.1', install : true)
install_headers('include/LibCommunist.h', 'include/NetOperationsComm.h', subdir : 'libcommunist')
pkg.generate (lib, name : 'libcommunist', version : '1.0.1', subdirs : 'libcommunist')

