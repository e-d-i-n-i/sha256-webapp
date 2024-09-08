from flask import Flask, request, jsonify # type: ignore
from hashlib import sha256
from flask_cors import CORS # type: ignore

app = Flask(__name__)
CORS(app)  # This will allow cross-origin requests

def preprocess_message(message):
    message_bin = ''.join(format(ord(char), '08b') for char in message)
    original_length = len(message_bin)
    message_bin += '1'
    while len(message_bin) % 512 != 448:
        message_bin += '0'
    message_bin += format(original_length, '064b')
    return message_bin

def right_rotate(value, bits):
    return (value >> bits) | (value << (32 - bits)) & 0xFFFFFFFF

def sha256_ch(x, y, z):
    return (x & y) ^ (~x & z)

def sha256_maj(x, y, z):
    return (x & y) ^ (x & z) ^ (y & z)

def sha256_sum0(x):
    return right_rotate(x, 2) ^ right_rotate(x, 13) ^ right_rotate(x, 22)

def sha256_sum1(x):
    return right_rotate(x, 6) ^ right_rotate(x, 11) ^ right_rotate(x, 25)

def sha256_sigma0(x):
    return right_rotate(x, 7) ^ right_rotate(x, 18) ^ (x >> 3)

def sha256_sigma1(x):
    return right_rotate(x, 17) ^ right_rotate(x, 19) ^ (x >> 10)

K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

def process_chunk(chunk, H):
    words = [int(chunk[i:i+32], 2) for i in range(0, len(chunk), 32)]
    for i in range(16, 64):
        s0 = sha256_sigma0(words[i - 15])
        s1 = sha256_sigma1(words[i - 2])
        words.append((words[i - 16] + s0 + words[i - 7] + s1) & 0xFFFFFFFF)
    a, b, c, d, e, f, g, h = H
    for i in range(64):
        S1 = sha256_sum1(e)
        ch = sha256_ch(e, f, g)
        temp1 = (h + S1 + ch + K[i] + words[i]) & 0xFFFFFFFF
        S0 = sha256_sum0(a)
        maj = sha256_maj(a, b, c)
        temp2 = (S0 + maj) & 0xFFFFFFFF
        h = g
        g = f
        f = e
        e = (d + temp1) & 0xFFFFFFFF
        d = c
        c = b
        b = a
        a = (temp1 + temp2) & 0xFFFFFFFF
    H[0] = (H[0] + a) & 0xFFFFFFFF
    H[1] = (H[1] + b) & 0xFFFFFFFF
    H[2] = (H[2] + c) & 0xFFFFFFFF
    H[3] = (H[3] + d) & 0xFFFFFFFF
    H[4] = (H[4] + e) & 0xFFFFFFFF
    H[5] = (H[5] + f) & 0xFFFFFFFF
    H[6] = (H[6] + g) & 0xFFFFFFFF
    H[7] = (H[7] + h) & 0xFFFFFFFF
    return H

def sha256(message):
    message_bin = preprocess_message(message)
    H = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ]
    for i in range(0, len(message_bin), 512):
        chunk = message_bin[i:i+512]
        H = process_chunk(chunk, H)
    hash_value = ''.join(format(h, '08x') for h in H)
    return hash_value

@app.route('/sha256', methods=['POST'])
def sha256_api():
    data = request.get_json()
    message = data.get('message')
    if not message:
        return jsonify({"error": "No message provided"}), 400
    hash_value = sha256(message)
    return jsonify({"message": message, "sha256": hash_value})

@app.route('/decrypt', methods=['POST'])
def decrypt_api():
    data = request.get_json()
    target_hash = data.get('hash')
    if not target_hash:
        return jsonify({"error": "No hash provided"}), 400
    
    # Load the word library
    try:
        with open('word_library.txt', 'r') as file:
            words = file.readlines()
    except FileNotFoundError:
        return jsonify({"error": "Word library not found"}), 500

    for word in words:
        word = word.strip()  # Remove any surrounding whitespace
        if sha256(word) == target_hash:
            return jsonify({"message": word, "sha256": target_hash})
    
    return jsonify({"error": "No matching word found"}), 404

if __name__ == '__main__':
    app.run(debug=True)
