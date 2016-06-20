# -*- coding: utf-8 -*-
#
# Copyright 2016 Bob Mottram <bob@robotics.uk.to>
#
# This file is part of python-omemo library.
#
# The python-omemo library is free software: you can redistribute it and/or
# modify it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or (at your
# option) any later version.
#
# python-omemo is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# the python-omemo library.  If not, see <http://www.gnu.org/licenses/>.
#

''' Helper functions for padding plaintext '''

from random import randint


def padding_add(plaintext):
    ''' Pad the text to a minimum of 255 characters, by adding random amount of
        spaces before and after plaintext.
    '''
    # get the padding length
    pad = 256
    while len(plaintext) > pad:
        pad = pad * 2

    # create padding strings
    pad_start = ' ' * randint(0, pad - len(plaintext))
    pad_end = ' ' * (pad - len(pad_start) - len(plaintext))

    # return padded plaintext
    return pad_start + plaintext + pad_end


def padding_remove(plaintext):
    ''' Strip the padding from plaintext '''
    return plaintext.strip(' ')
