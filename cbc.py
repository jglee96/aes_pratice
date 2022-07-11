from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from hashlib import sha256


class AES_cbc:
    def __init__(self, key):
        self.key = key
        self.iv = ""

    def encrypt(self, data):
        cipher = AES.new(self.key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(data, AES.block_size))
        self.iv = b64encode(cipher.iv).decode("utf-8")
        ct = b64encode(ct_bytes).decode("utf-8")
        return ct

    def decrypt(self, data):
        try:
            iv = b64decode(self.iv)
            ct = b64decode(data)
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            pt = unpad(cipher.decrypt(ct), AES.block_size)
            return pt
        except (ValueError, KeyError):
            print("Incorrect decryption")


if __name__ == "__main__":
    r = "1234"
    key = sha256(r.encode()).digest()
    aes = AES_cbc(key)
    msg = "Good"

    enc = aes.encrypt(msg.encode())
    print(enc)

    dec = aes.decrypt(enc.encode())
    print(dec.decode())
