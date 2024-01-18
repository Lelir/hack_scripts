import struct
from binascii import hexlify
import sys

def detect_keepass_version(data):
    file_signature = hexlify(data[:8])

    if file_signature == b'03d9a29a67fb4bb5' or file_signature == b'03d9a29a66fb4bb5':
        # 2.X or 2.X pre-release
        return "KDBX 2.X"

    elif file_signature == b'03d9a29a65fb4bb5':
        # 1.X
        return "KDB 1.X"

    elif file_signature == b'03d9a29a31fb4bb5':
        # KDBX 3.1
        return "KDBX 3.1"

    elif file_signature == b'03d9a29a32fb4bb5':
        # KDBX 4
        kdf_params_index = 12  # Adjust this value based on your knowledge of the file structure

        # Extract KDF parameters
        version = struct.unpack("<H", data[kdf_params_index:kdf_params_index+2])[0]
        kdf_params = data[kdf_params_index+2:-1]  # Exclude the null terminator

        if version == 0x0100:
            return "KDBX 4 with KDF parameters: {}".format(kdf_params)

        else:
            return "Unknown version with KDF parameters"

    else:
        return "Unknown KeePass database version"


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: %s <kdb[x] file>\n" % sys.argv[0])
        sys.exit(-1)

    filename = sys.argv[1]

    with open(filename, 'rb') as f:
        data = f.read()

    version_info = detect_keepass_version(data)
    print(f"The KeePass database is of version: {version_info}")
