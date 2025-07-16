import base64alg

# Base64 encoded string
encoded_string = "8g8WFhnWyiEZHBYOyw=="

# Decode the Base64 string to get the binary data
decoded_bytes = base64.b64decode(encoded_string)

# Key
key = "WOQ74L"

# Repeat the key to match the length of the decoded bytes
repeated_key = (key * (len(decoded_bytes) // len(key) + 1))[:len(decoded_bytes)]

# XOR each byte
decrypted_bytes = bytes([b1 ^ ord(b2) for b1, b2 in zip(decoded_bytes, repeated_key)])

# Convert the decrypted bytes to a string (if it's a string)
try:
    decrypted_string = decrypted_bytes.decode('utf-8')
    print(f"Decrypted string: {decrypted_string}")
except UnicodeDecodeError:
    print(f"Decrypted bytes: {decrypted_bytes}")