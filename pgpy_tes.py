#!/usr/bin/python

import pgpy
import shutil
import six

from pgpy.constants import (
    PubKeyAlgorithm, KeyFlags, HashAlgorithm,
    SymmetricKeyAlgorithm, CompressionAlgorithm)
from subprocess import Popen, PIPE
from tempfile import mkdtemp


def gpg_encrypt(key, data):
    gpghome = mkdtemp()

    p = Popen(['gpg', '--homedir=%s' % gpghome, '--batch', '--import'],
              stdin=PIPE)
    p.communicate(input=six.b(str(key)))
    p = Popen(['gpg', '--homedir=%s' % gpghome, '-a',
               '--encrypt', '--recipient', key.fingerprint],
              stdout=PIPE, stdin=PIPE)
    enc_data = p.communicate(input=six.b(data))[0]
    shutil.rmtree(gpghome)
    return enc_data


def gpg_decrypt(key, enc_data):
    gpghome = mkdtemp()

    p = Popen(['gpg', '--homedir=%s' % gpghome, '--batch', '--import'],
              stdin=PIPE)
    p.communicate(input=six.b(str(key)))
    p = Popen(['gpg', '--homedir=%s' % gpghome, '-a',
               '--decrypt'],
              stdout=PIPE, stdin=PIPE)
    data = p.communicate(input=enc_data)[0]
    shutil.rmtree(gpghome)
    return str(data)


def pgpy_create_key():
    # we can start by generating a primary key. For this example, we'll use RSA, but it could be DSA or ECDSA as well
    key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 4096)

    # we now have some key material, but our new key doesn't have a user ID yet, and therefore is not yet usable!
    uid = pgpy.PGPUID.new('Abraham Lincoln', comment='Honest Abe', email='abraham.lincoln@whitehouse.gov')

    # now we must add the new user id to the key. We'll need to specify all of our preferences at this point
    # because PGPy doesn't have any built-in key preference defaults at this time
    # this example is similar to GnuPG 2.1.x defaults, with no expiration or preferred keyserver
    key.add_uid(uid, usage={KeyFlags.Sign, KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage},
                hashes=[HashAlgorithm.SHA256, HashAlgorithm.SHA384, HashAlgorithm.SHA512, HashAlgorithm.SHA224],
                ciphers=[SymmetricKeyAlgorithm.AES256, SymmetricKeyAlgorithm.AES192, SymmetricKeyAlgorithm.AES128],
                compression=[CompressionAlgorithm.ZLIB, CompressionAlgorithm.BZ2, CompressionAlgorithm.ZIP, CompressionAlgorithm.Uncompressed])
    return key


def pgpy_encrypt(key, data):
    message = pgpy.PGPMessage.new(data)
    enc_message = key.pubkey.encrypt(message)
    return bytes(enc_message)


def pgpy_decrypt(key, enc_data):
    message = pgpy.PGPMessage.from_blob(enc_data)
    return str(key.decrypt(message).message)


if __name__ == '__main__':
    key = pgpy_create_key()
    gpg_enc = gpg_encrypt(key, 'gpg encrypted')
    pgpy_enc = pgpy_encrypt(key, 'pgpy encrypted')

    data = gpg_decrypt(key, gpg_enc)
    print("===> gpg->gpg: " + data)
    data = gpg_decrypt(key, pgpy_enc)
    print("===> pgpy->gpg: " + data)
    data = pgpy_decrypt(key, gpg_enc)
    print("===> gpg->pgpy: " + data)
    data = pgpy_decrypt(key, pgpy_enc)
    print("===> pgpy->pgpy: " + data)
