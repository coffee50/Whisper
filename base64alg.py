import base64

def encrypt(message, key):
    message_bytes = message.encode('utf-8')
    base64_bytes = base64.b64encode(message_bytes)
    base64_message = base64_bytes.decode('utf-8')
    return base64_message

def decrypt(message, key):
    base64_bytes = message.encode('utf-8')
    message_bytes = base64.b64decode(base64_bytes)
    message = message_bytes.decode('utf-8')
    return message
