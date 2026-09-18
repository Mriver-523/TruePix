# libpws #

A library for interpreting PWS (prover worksheet) files, which we use
to describe arithmetic circuits.

This code is ported from [Zebra](https://github.com/pepper-project/zebra/).
I've traded the dependency on libchacha for a dependency on libcrypto,
rewritten the build system, and done other cleanup.

## Building ##

On debian-ish systems, you'll probably need the following:

    apt-get install build-essential g++ automake pkg-config \
                    libssl-dev libtool libtool-bin libgmp-dev

The above should translate straightforwardly to other package managers: you'll
need a C++11-compatible compiler (I've tested with g++ 5, 6, and 7), automake,
pkg-config, libtool, and development headers for OpenSSL.
(If you can't figure out what packages you need to install, please contact me!)

Next, to build the software:

    ./autogen.sh
    ./configure
    make -j4        # for example

# license #

Copyright 2017 Riad S. Wahby <rsw@cs.stanford.edu> and the Hyrax authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
