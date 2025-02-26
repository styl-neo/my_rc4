from Crypto.Cipher import ARC4
from main import rc4_cipher
import pytest
import random

def gen_param():
    keylength = random.randint(5, 16)
    ptlength = random.randint(1, 1024)

    return (random.randbytes(keylength), random.randbytes(ptlength))

@pytest.mark.parametrize(
        "key,plaintext",
        [gen_param() for _ in range(10)]
)

def test_encrypt(key, plaintext):
    errored = []

    cipher = ARC4.new(key)
    ciphertext = rc4_cipher(plaintext, key)
    if not ciphertext == cipher.encrypt(plaintext):
        errored.append("Failed cipher")
    pt = rc4_cipher(ciphertext, key)
    if not pt == plaintext:
        errored.append("Failed plaintext")
    assert not errored 
