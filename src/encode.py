import base64
import json
import zlib
import sys

def encode_config(config):
    json_str = json.dumps(config, indent=4).encode()
    compressed_data = zlib.compress(json_str)
    original_data_len = len(json_str)
    header = original_data_len.to_bytes(4, byteorder='big')
    encoded_data = base64.urlsafe_b64encode(header + compressed_data).decode().rstrip("=")
    return encoded_data

if __name__ == "__main__":

    if len(sys.argv) < 2:
        print("Usage: python3 encode.py '<json_string>'")
        sys.exit(1)
    json_string = sys.argv[1]

    try:
        config = json.loads(json_string)
        encoded_string = encode_config(config)
        print(encoded_string)

    except json.JSONDecodeError:
        print("Invalid JSON string.")
