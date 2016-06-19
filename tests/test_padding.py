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

import os

import pytest

from omemo.padding import *

def test_padding_length():
    assert(len(padding_add(u'Oh Romemo!')) == 256)
    assert(len(padding_add(u'Wherefore art thou Romeo?')) == 256)

    teststr=u'JULIET O Romeo, Romeo! wherefore art thou Romeo? Deny thy father and refuse thy name; Or, if thou wilt not, be but sworn my love, And I\'ll no longer be a Capulet. ROMEO [Aside] Shall I hear more, or shall I speak at this? JULIET \'Tis but thy name that is my enemy; Thou art thyself, though not a Montague. What\'s Montague? it is nor hand, nor foot, Nor arm, nor face, nor any other part Belonging to a man. O, be some other name! What\'s in a name? that which we call a rose By any other name would smell as sweet; So Romeo would, were he not Romeo call\'d, Retain that dear perfection which he owes Without that title. Romeo, doff thy name, And for that name which is no part of thee Take all myself.'
    assert(len(padding_add(teststr)) == 1024)

def test_padding_offset():
    # This tests that the padding offsets for the same string are different each time
    # The test could fail, but with very low probability
    padded = []
    teststr=u'LOL'
    padded.append(padding_add(teststr))
    padded.append(padding_add(teststr))
    padded.append(padding_add(teststr))
    same_strings = 0
    if padded[0] == padded[1]:
        same_strings = same_strings + 1
    if padded[0] == padded[2]:
        same_strings = same_strings + 1
    if padded[1] == padded[2]:
        same_strings = same_strings + 1
    assert(same_strings < 2)

def test_padding_remove():
    teststr=u'Oh Romemo!'
    padded = padding_add(teststr)
    assert(len(padding_remove(padded)) == len(teststr))
    assert(padding_remove(padded) == teststr)
