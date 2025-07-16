import base64

def encrypt(message, key):
    digit_sum = sum(int(c) for c in key if c.isdigit())
    letter_sum = sum(ord(c) for c in key if c.isalpha())
    key_modifier = (digit_sum + letter_sum) % 256 #modulo added for safety

    encrypted_bytes = bytearray()
    for char in message:
        encrypted_bytes.append((ord(char) + key_modifier) % 256)

    encoded_output = base64.b64encode(encrypted_bytes).decode('utf-8')
    return encoded_output

def decrypt(message, key):
    digit_sum = sum(int(c) for c in key if c.isdigit())
    letter_sum = sum(ord(c) for c in key if c.isalpha())
    key_modifier = (digit_sum + letter_sum) % 256

    try:
        decoded_bytes = base64.b64decode(message)
        decrypted_message = ""
        for byte in decoded_bytes:
            decrypted_message += chr((byte - key_modifier) % 256)
        return decrypted_message
    except Exception as e:
        return f"Error decoding: {e}"
