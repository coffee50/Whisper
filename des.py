import base64

def encrypt(message, key):
    key_int = sum(ord(c) for c in key)

    encrypted_bytes = bytearray()
    for char in message:
        encrypted_bytes.append((ord(char) + key_int) % 256)
    encoded_output = base64.b64encode(encrypted_bytes).decode('utf-8')
    return encoded_output

def decrypt(message, key):
    key_int = sum(ord(c) for c in key)
    try:
        decoded_bytes = base64.b64decode(message)
        decrypted_message = ""
        for byte in decoded_bytes:
            decrypted_message += chr((byte - key_int) % 256)
        return decrypted_message
    except Exception as e:
        return f"Error decoding: {e}"