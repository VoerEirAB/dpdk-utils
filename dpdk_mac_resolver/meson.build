################################################################################
# Copyright (c) 2025-present VoerEir AB - All Rights Reserved                  #
# Unauthorized copying of this file, via any medium is strictly prohibited     #
# Proprietary and confidential                                                 #
# Written by Priyangshu Bose <priyangshu@voereir.com>, Apr 2025                #
################################################################################

# meson file, for building this example as part of a main DPDK build.
#
# To build this example as a standalone application with an already-installed
# DPDK instance, use 'make'
# Define the project
project('dpdk-utils', 'c',
    version: '1.0',
    meson_version: '>=0.53.2',
    default_options: ['c_std=gnu11'])

# Get the C compiler
cc = meson.get_compiler('c')

# Check if the compiler has the 'getaddrinfo' function
if not cc.has_function('getaddrinfo')
  error('Your system does not support getaddrinfo. Please use a POSIX-compliant system.')
endif

# Find the DPDK library using pkg-config
dpdk = dependency('libdpdk', method: 'pkg-config',
                  required: true,
                  static: false)

# Define source files
src = files('dpdk_mac_resolver.c')

# Define the executable target
executable('dpdk-mac-resolver', src,
    dependencies: [dpdk],
    link_args: '-lnsl',
    install: true)
