# -*- coding: utf-8 -*-
#
# Copyright 2014 Jonathan Zdziarski <jonathan@zdziarski.com>
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
# list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its contributors
# may be used to endorse or promote products derived from this software without
# specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import logging
from struct import pack, unpack

from Crypto.Cipher import AES
from Crypto.Util import strxor

log = logging.getLogger('gajim.plugin_system.omemo')


def gcm_rightshift(vec):
    for x in range(15, 0, -1):
        c = vec[x] >> 1
        c |= (vec[x - 1] << 7) & 0x80
        vec[x] = c
    vec[0] >>= 1
    return vec


def gcm_gf_mult(a, b):
    mask = [0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01]
    poly = [0x00, 0xe1]

    Z = [0] * 16
    V = [c for c in a]

    for x in range(128):
        if b[x >> 3] & mask[x & 7]:
            Z = [V[y] ^ Z[y] for y in range(16)]
        bit = V[15] & 1
        V = gcm_rightshift(V)
        V[0] ^= poly[bit]
    return Z


def ghash(h, auth_data, data):
    u = (16 - len(data)) % 16
    v = (16 - len(auth_data)) % 16

    x = auth_data + chr(0) * v + data + chr(0) * u
    x += pack('>QQ', len(auth_data) * 8, len(data) * 8)

    y = [0] * 16
    vec_h = [ord(c) for c in h]

    for i in range(0, len(x), 16):
        block = [ord(c) for c in x[i:i + 16]]
        y = [y[j] ^ block[j] for j in range(16)]
        y = gcm_gf_mult(y, vec_h)

    return ''.join(chr(c) for c in y)


def inc32(block):
    counter, = unpack('>L', block[12:])
    counter += 1
    return block[:12] + pack('>L', counter)


def gctr(k, icb, plaintext):
    y = ''
    if len(plaintext) == 0:
        return y

    aes = AES.new(k)
    cb = icb

    for i in range(0, len(plaintext), aes.block_size):
        cb = inc32(cb)
        encrypted = aes.encrypt(cb)
        plaintext_block = plaintext[i:i + aes.block_size]
        y += strxor.strxor(plaintext_block, encrypted[:len(plaintext_block)])

    return y


def gcm_decrypt(k, iv, encrypted, auth_data, tag):
    aes = AES.new(k)
    h = aes.encrypt(chr(0) * aes.block_size)

    if len(iv) == 12:
        y0 = iv + "\x00\x00\x00\x01"
    else:
        y0 = ghash(h, '', iv)

    decrypted = gctr(k, y0, encrypted)
    s = ghash(h, auth_data, encrypted)

    t = aes.encrypt(y0)
    T = strxor.strxor(s, t)
    if T != tag:
        raise ValueError('Decrypted data is invalid')
    else:
        return decrypted


def gcm_encrypt(k, iv, plaintext, auth_data):
    aes = AES.new(k)
    h = aes.encrypt(chr(0) * aes.block_size)

    if len(iv) == 12:
        y0 = iv + "\x00\x00\x00\x01"
    else:
        y0 = ghash(h, '', iv)

    encrypted = gctr(k, y0, plaintext)
    s = ghash(h, auth_data, encrypted)

    t = aes.encrypt(y0)
    T = strxor.strxor(s, t)
    return (encrypted, T)


def aes_encrypt(key, nonce, plaintext):
    """ Use AES128 GCM with the given key and iv to encrypt the payload. """
    c, t = gcm_encrypt(key, nonce, plaintext, '')
    result = c + t
    log.info(result)
    return result


def aes_decrypt(key, nonce, payload):
    """ Use AES128 GCM with the given key and iv to decrypt the payload. """
    ciphertext = payload[:-16]
    mac = payload[-16:]
    return gcm_decrypt(key, nonce, ciphertext, '', mac)


class NoValidSessions(Exception):
    pass
