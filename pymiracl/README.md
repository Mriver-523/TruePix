# miracl for Python

This directory includes a library for calling MIRACL from Python. Most notably, this
includes a couple implementations of fast multiexponentiation algorithms; see
`src/pymiracl/multiexp.c`.

To actually call this library from python, use the MiraclEC object defined in
the `python/pymiracl` module.

## building ##

On debian-ish systems, you'll probably need the following:

    apt-get install build-essential gcc automake pkg-config libtool libtool-bin

Other package managers should have similar requirements: you'll need a modern C
compiler (I've tested with gcc 4, 5, 6, and 7), automake, pkg-config, and libtool.

You will also need python (I've tested 2.x and 3.x) and the CFFI package to use
the Python code. It also works with PyPy (I've tested 5.x).

(If you can't figure out what packages you need, please contact me!)

Next, to build the software:

    ./autogen.sh
    ./configure
    make -j4        # for example

# license #

Copyright 2018 Riad S. Wahby <rsw@cs.stanford.edu> and the Hyrax authors.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
