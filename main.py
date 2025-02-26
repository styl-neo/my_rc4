def rc4_cipher(pt: bytes, key: bytes) -> bytes:
    keylength = len(key)
    assert 1 <= keylength <= 16

    s = [x for x in range(256)]
    # KSA
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % keylength]) % 256
        s[i], s[j] = s[j], s[i]

    # Gen
    out = bytearray()
    i, j = 0, 0
    for _ in range(len(pt)):
        i = (i+1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        t = (s[i] + s[j]) % 256
        K = s[t]
        out.append(K)
    
    # XORing pt and out
    return bytes(p ^ e for p, e in zip(pt, bytes(out)))


def main() -> None:
    key = b"\x01\xae"
    plaintext = bytes("Hello there!", "UTF8")
    ciphertest = rc4_cipher(plaintext, key)

    print(rc4_cipher(ciphertest, key))
    print("f56f02d7093d7b06e4e55710")


if __name__ == "__main__":
    main()
