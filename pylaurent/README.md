# pylaurent

This is a helper library that lets Python call NTL through CFFI.
It is used in [BCCGP-sqrt](https://github.com/hyraxZK/bccgp) for polynomial multiplication.

# Building #

On Debian-ish systems, you'll probably need the following:

    apt-get install build-essential g++ automake pkg-config \
                    libtool libtool-bin libgmp-dev

This library also requires [NTL 10.x](http://www.shoup.net/ntl/). This might be as simple as

	apt-get install libntl-dev

But several distributions (including Debian 9.x) do not package recent enough versions.
Lucky you! You get to build a newer version.

## NTL ##

You only need to do this if your distribution doesn't provide NTL 10.x. If you've
already got it, you can skip to the next section.

We'll install this library in `$HOME/toolchains`, so first we need to make
that directory, get the source, and unpack it:

    mkdir -p $HOME/toolchains/src
    cd $HOME/toolchains/src
    wget http://shoup.net/ntl/ntl-10.5.0.tar.gz
    tar xzvf ntl-10.5.0.tar.gz
    cd ntl-10.5.0/src

Now we're going to configure and build NTL. The following options are known
to work, assuming you have a C++14-compatible compiler (e.g., g++ >= 5).
Otherwise, change `NTL_STD_CXX14` to `NTL_STD_CXX11` immediately below.

    ./configure DEF_PREFIX=/usr PREFIX=$HOME/toolchains SHARED=on \
                NTL_THREAD_BOOST=on NTL_STD_CXX14=on
    make -j4		# for example
    make install

The above will take a while because it'll run some tuning scripts. Give it five minutes or so.

## pylaurent ##

Now we're ready to build pylaurent:

	./autogen.sh
	# if you installed NTL in the prior step, use the following command:
	./configure --with-ntl=$HOME/toolchains
	# otherwise, just call ./configure
    make -j4		# for example

## Making sure things wiggle ##

If you don't have it installed already, you should first install Python's CFFI package:

	apt-get install python-cffi

Now:

	cd python
	python -m pylaurent

If you don't get any errors, you ought to be all set.

## contact ##

	rsw@cs.stanford.edu

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
