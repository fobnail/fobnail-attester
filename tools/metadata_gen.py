import cbor
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.serialization import load_der_private_key
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

def hexdump(data):
    for i in range(len(data)):
        x = data[i]
        end = '\n' if i + 1 >= 16 and (i + 1) % 16 == 0 else ''
        print(f'0x{x:02x}, ', end=end)


# Key generation:
# openssl genpkey -algorithm ED25519 > /tmp/key.priv
# openssl pkey -in /tmp/key.priv -noout -text
# ED25519 Private-Key:
# priv:
#     12:7d:73:f1:d3:b5:bc:08:63:7e:0c:fb:67:06:d6:
#     12:0e:3c:ce:90:69:87:4c:a7:0d:ce:f0:44:95:9a:
#     ec:02
# pub:
#     4a:d9:d7:fe:ba:04:b3:83:a1:9d:54:d0:66:1c:97:
#     69:58:13:b7:dc:24:29:09:94:c7:c7:f9:92:39:6e:
#     79:24

rsa_key = bytes([
    0x30, 0x82, 0x04, 0xa2, 0x02, 0x01, 0x00, 0x02, 0x82, 0x01, 0x01, 0x00,
    0xb1, 0x9d, 0x49, 0x08, 0x82, 0xd4, 0xfd, 0x73, 0xec, 0xe4, 0xe1, 0x1d,
    0x81, 0x84, 0xdc, 0x4c, 0xd6, 0xa2, 0x33, 0xd5, 0x25, 0x2f, 0x30, 0xc1,
    0x3f, 0xac, 0x17, 0x14, 0x22, 0x6b, 0xce, 0xaf, 0xaf, 0x9a, 0xfd, 0xd1,
    0x9c, 0xb5, 0xf1, 0x96, 0x82, 0xb8, 0x82, 0x86, 0xef, 0xe7, 0x48, 0x9d,
    0x52, 0x1e, 0xcf, 0xfe, 0x44, 0x87, 0x37, 0x58, 0x7c, 0x1b, 0xb7, 0xb6,
    0x4c, 0xfb, 0xce, 0x95, 0xdd, 0x42, 0x6c, 0x4d, 0x43, 0xaa, 0xaa, 0x37,
    0x6e, 0xdc, 0x88, 0x55, 0xbf, 0x54, 0xf9, 0x33, 0x35, 0x1e, 0x63, 0xd0,
    0x46, 0x06, 0x9c, 0x4a, 0x70, 0x69, 0x6c, 0x4a, 0x1a, 0x70, 0x1f, 0x7e,
    0x80, 0x63, 0x7b, 0xa9, 0xd3, 0x0d, 0xb6, 0x59, 0x3c, 0x9f, 0xcf, 0xeb,
    0x53, 0x88, 0x17, 0x76, 0xf8, 0xb8, 0x94, 0xf4, 0x40, 0xb4, 0xfb, 0xf6,
    0x1b, 0x95, 0xb6, 0xa1, 0x50, 0xf4, 0x43, 0x03, 0x30, 0x57, 0xc9, 0xce,
    0xd1, 0xe8, 0xbf, 0xcf, 0x09, 0x61, 0x02, 0xbd, 0xa9, 0xef, 0xed, 0x6d,
    0x2e, 0x2a, 0x5c, 0xc3, 0xd5, 0x1e, 0x83, 0xb2, 0xc5, 0x14, 0x22, 0xa2,
    0x1f, 0x24, 0x5c, 0x6f, 0x86, 0xe5, 0x75, 0x19, 0x7e, 0x09, 0xc3, 0x3e,
    0x08, 0x61, 0x0e, 0xfa, 0x35, 0x2e, 0xa5, 0xbd, 0xb8, 0x5e, 0x17, 0x85,
    0xfb, 0x35, 0x18, 0xcd, 0x29, 0xa5, 0x9b, 0xf7, 0x56, 0xf6, 0x92, 0xae,
    0x4a, 0x20, 0x8a, 0x9f, 0x33, 0xe0, 0x9a, 0x39, 0x2e, 0x7c, 0x29, 0x82,
    0xef, 0x32, 0xcc, 0xd0, 0x99, 0xb9, 0x2b, 0x44, 0xac, 0x9b, 0x71, 0xdf,
    0x1c, 0x9c, 0x74, 0x95, 0x7e, 0x7d, 0x85, 0x1e, 0x34, 0xea, 0x5f, 0x49,
    0x19, 0x38, 0xe7, 0xb0, 0x3c, 0x2d, 0x6f, 0x17, 0x95, 0x7b, 0xa7, 0xfc,
    0x80, 0xf4, 0xe6, 0x5f, 0xfc, 0xad, 0x0d, 0xa1, 0x9d, 0xdf, 0x03, 0x77,
    0x57, 0xbf, 0x54, 0xdd, 0x02, 0x03, 0x01, 0x00, 0x01, 0x02, 0x82, 0x01,
    0x00, 0x2d, 0x41, 0xb1, 0x89, 0x4c, 0xa4, 0xee, 0xcb, 0xea, 0x11, 0xcb,
    0xd6, 0x93, 0xd9, 0x01, 0xb5, 0x46, 0x7f, 0x60, 0x0b, 0xb0, 0x84, 0xdc,
    0xbc, 0x70, 0xf7, 0xed, 0x8d, 0x80, 0xd3, 0xcd, 0x7f, 0x70, 0x94, 0x62,
    0x96, 0x55, 0x82, 0xfa, 0xc2, 0xea, 0x1e, 0x0f, 0x8c, 0x48, 0x76, 0xbb,
    0x46, 0xf2, 0xd4, 0xcd, 0x14, 0xb1, 0xeb, 0x6e, 0x4b, 0xca, 0x9b, 0xd9,
    0x6c, 0xc7, 0x22, 0xe6, 0x59, 0xc3, 0x5e, 0x18, 0x70, 0x7b, 0x8c, 0x72,
    0x00, 0xdb, 0xeb, 0xaf, 0x85, 0x81, 0xd2, 0x2a, 0x09, 0x45, 0x40, 0xb0,
    0x18, 0x32, 0xaf, 0x9e, 0x85, 0x4d, 0x2d, 0x5f, 0x9d, 0x66, 0x2d, 0x29,
    0xa9, 0x37, 0x17, 0xa2, 0x3b, 0xfc, 0x7e, 0x22, 0xf7, 0x8b, 0xfe, 0x00,
    0xa1, 0xaa, 0xd0, 0x23, 0x82, 0x7a, 0x0f, 0xb6, 0x4c, 0xa2, 0x6c, 0x3b,
    0x43, 0x53, 0x76, 0x0b, 0x6a, 0x01, 0x51, 0xab, 0xfd, 0x28, 0x19, 0x93,
    0xa2, 0x61, 0x8c, 0x26, 0x44, 0x33, 0x75, 0x33, 0x62, 0xc6, 0x74, 0xe7,
    0x29, 0x3e, 0xa7, 0xa4, 0x9c, 0xcf, 0x3e, 0xed, 0x0e, 0x65, 0x19, 0xd5,
    0xef, 0x69, 0x7c, 0x02, 0xf4, 0x22, 0x4a, 0x59, 0x54, 0x2e, 0x46, 0x4b,
    0x34, 0xfc, 0x67, 0x92, 0xb4, 0xbb, 0x23, 0xd4, 0x9c, 0xce, 0x0e, 0x87,
    0xc5, 0x7b, 0x45, 0x5a, 0xf1, 0xf5, 0xd3, 0x46, 0x03, 0xd5, 0x5b, 0x7f,
    0xa4, 0xc7, 0x53, 0xa4, 0x00, 0xff, 0xdd, 0xa4, 0x0e, 0xfc, 0x98, 0x12,
    0xbc, 0x67, 0x49, 0xea, 0x37, 0x49, 0x8e, 0x8c, 0x83, 0xd3, 0x9c, 0x9f,
    0xfa, 0xe6, 0x90, 0xa2, 0x89, 0x55, 0xa5, 0x1e, 0x07, 0x78, 0xca, 0xf2,
    0x81, 0x05, 0xc5, 0xb3, 0x32, 0x7b, 0x45, 0xcd, 0x82, 0x61, 0x88, 0x1f,
    0x4e, 0x6d, 0x32, 0xcb, 0x75, 0x59, 0x70, 0x58, 0xa8, 0x5b, 0x32, 0xcc,
    0x76, 0x70, 0x98, 0xc8, 0x15, 0x02, 0x81, 0x81, 0x00, 0xe4, 0x4c, 0x2e,
    0xd3, 0x7c, 0x39, 0x3a, 0x84, 0x24, 0xbf, 0x34, 0x43, 0x1d, 0xcd, 0x85,
    0x74, 0x91, 0x7d, 0xe9, 0xe2, 0x16, 0x11, 0x92, 0xc9, 0x32, 0x37, 0x3a,
    0x17, 0x29, 0x33, 0x36, 0xd9, 0x97, 0x9c, 0x13, 0x6a, 0x57, 0x8a, 0xf9,
    0xd5, 0xfe, 0x21, 0x22, 0xa4, 0x4c, 0x23, 0x8a, 0xda, 0x7f, 0x96, 0xa7,
    0xe9, 0x94, 0xee, 0xaa, 0xf5, 0xa5, 0x28, 0xb1, 0xc8, 0xda, 0x5a, 0x69,
    0xd4, 0xbb, 0x3f, 0x47, 0x57, 0xb6, 0x1e, 0x8e, 0x87, 0x41, 0xdb, 0x6c,
    0x95, 0xd2, 0xd6, 0x29, 0x17, 0xe3, 0x10, 0x8a, 0x3d, 0x6f, 0xee, 0x2b,
    0x9c, 0x77, 0x7d, 0x69, 0x51, 0x9f, 0x1f, 0x9b, 0x4a, 0xde, 0xac, 0x2c,
    0x02, 0x78, 0x41, 0x2a, 0x4c, 0x0e, 0x99, 0x02, 0x49, 0xb1, 0xaa, 0xc6,
    0x74, 0x59, 0x1d, 0x61, 0x0c, 0x80, 0x72, 0x5e, 0xe6, 0xa9, 0xed, 0x49,
    0x0f, 0xff, 0xc0, 0x0c, 0x6f, 0x02, 0x81, 0x81, 0x00, 0xc7, 0x2a, 0xaf,
    0x14, 0x94, 0xb3, 0x3f, 0xb0, 0x13, 0xb8, 0x6f, 0xb9, 0x05, 0x47, 0x6f,
    0x40, 0x31, 0x1a, 0x58, 0xe7, 0xc9, 0xe0, 0xb5, 0x69, 0x26, 0x52, 0x37,
    0x07, 0xaa, 0x7a, 0xdd, 0xfd, 0xbb, 0x6e, 0xab, 0xac, 0xdb, 0x5e, 0xa5,
    0xaa, 0xd3, 0x19, 0x22, 0xcc, 0xa1, 0x55, 0xcc, 0x3f, 0xba, 0xca, 0x32,
    0xb4, 0x21, 0x4e, 0x89, 0x14, 0x32, 0xbe, 0x50, 0xec, 0x60, 0x81, 0x29,
    0xb8, 0x2b, 0x55, 0x89, 0xaa, 0x7e, 0xfd, 0x6b, 0xc2, 0x97, 0xf9, 0x28,
    0x6a, 0x28, 0xca, 0x32, 0x79, 0x4b, 0xb3, 0xb6, 0x31, 0x8f, 0xda, 0x17,
    0x4f, 0x9f, 0x12, 0xab, 0xc2, 0x11, 0x85, 0x41, 0x7d, 0x81, 0x68, 0x13,
    0xf8, 0xd2, 0xcf, 0x87, 0x6d, 0x0f, 0xf9, 0x02, 0x9b, 0xd6, 0x02, 0xd0,
    0x6a, 0x35, 0x38, 0xc7, 0xfe, 0xc5, 0x96, 0xd4, 0xcc, 0xc4, 0xd4, 0xfd,
    0x35, 0x94, 0xaf, 0xb1, 0x73, 0x02, 0x81, 0x80, 0x31, 0xdd, 0xbe, 0x20,
    0xad, 0xb2, 0xa6, 0x68, 0x74, 0xca, 0x5a, 0xf5, 0x0a, 0x0e, 0x79, 0x47,
    0x13, 0xfc, 0x87, 0xd8, 0xbd, 0x6f, 0x4b, 0x3b, 0xad, 0x3f, 0x48, 0xee,
    0x04, 0x2e, 0xce, 0x9d, 0x4a, 0xb3, 0x69, 0xbe, 0x41, 0xae, 0xf6, 0x91,
    0x5a, 0x78, 0x0c, 0x64, 0x0c, 0xc9, 0x7a, 0xab, 0xed, 0x50, 0x90, 0x0e,
    0xc2, 0x5c, 0x3b, 0x75, 0x7a, 0x84, 0xe0, 0x08, 0x7a, 0x41, 0x63, 0x7a,
    0x77, 0x08, 0x04, 0x62, 0x51, 0x42, 0x6d, 0x69, 0x77, 0xe6, 0x20, 0xda,
    0xbc, 0xf9, 0xd0, 0x72, 0x0a, 0x43, 0xf3, 0x9e, 0x25, 0xd3, 0xc5, 0x2c,
    0xe1, 0x20, 0xc0, 0x9f, 0x76, 0x7d, 0x65, 0xe3, 0x3d, 0xae, 0x27, 0xd2,
    0xc6, 0x47, 0x9d, 0xa0, 0x8d, 0x53, 0xb8, 0x9f, 0x36, 0x32, 0x92, 0x34,
    0x99, 0xbe, 0x84, 0x13, 0x41, 0xff, 0x39, 0x61, 0x72, 0xde, 0x84, 0xa5,
    0xfc, 0xfc, 0x0a, 0xfb, 0x02, 0x81, 0x80, 0x53, 0xa4, 0x6e, 0x60, 0xc3,
    0x4e, 0x40, 0x09, 0xef, 0x4e, 0x3e, 0xc5, 0x42, 0x1d, 0x4c, 0xf0, 0x75,
    0x6e, 0xae, 0x35, 0xb1, 0xc7, 0x88, 0x08, 0x3f, 0xca, 0xb9, 0x47, 0xa3,
    0xe5, 0xf3, 0xc2, 0xb2, 0x6b, 0x78, 0xf7, 0xa0, 0x2d, 0x30, 0x7f, 0xfc,
    0x25, 0x8b, 0x42, 0xca, 0xe2, 0xa0, 0x63, 0x87, 0x4b, 0x91, 0x5d, 0xaa,
    0xbb, 0x33, 0xc0, 0x62, 0xcb, 0x20, 0x6b, 0x14, 0xe0, 0x49, 0xa8, 0x09,
    0xb2, 0xe3, 0x9c, 0xd1, 0xb6, 0x16, 0x02, 0x64, 0x16, 0x84, 0x4d, 0x89,
    0x11, 0xd9, 0x7e, 0xad, 0x37, 0x2c, 0xe5, 0xc5, 0x96, 0xfe, 0xc1, 0x36,
    0x79, 0xfd, 0xde, 0x03, 0xc3, 0xa5, 0xcc, 0x52, 0x83, 0x66, 0x17, 0xd2,
    0x58, 0xcb, 0x74, 0x17, 0x08, 0x29, 0x7b, 0x4e, 0xb6, 0x61, 0xd6, 0xa8,
    0xc1, 0x4e, 0xe4, 0x85, 0x10, 0xa2, 0x0f, 0xd8, 0xfd, 0xe5, 0xd5, 0x11,
    0xbb, 0x73, 0x57, 0x02, 0x81, 0x80, 0x46, 0xc1, 0x05, 0x6f, 0xf4, 0x5b,
    0x47, 0xf2, 0xb7, 0x19, 0x5c, 0x1a, 0xee, 0x8e, 0xf6, 0xef, 0x08, 0x69,
    0xdf, 0x17, 0xe2, 0xb8, 0x96, 0x6c, 0xd1, 0x23, 0x36, 0xd9, 0xc5, 0xab,
    0x20, 0xc1, 0x07, 0xaa, 0xd7, 0x71, 0x00, 0x94, 0x2a, 0xad, 0x6f, 0xd0,
    0xb4, 0x3f, 0x89, 0xc0, 0x83, 0x74, 0x67, 0xaf, 0xa9, 0xd7, 0x59, 0x5d,
    0x14, 0xbc, 0x88, 0x65, 0x78, 0x6e, 0xf3, 0x06, 0x88, 0xba, 0x22, 0x9c,
    0x96, 0x77, 0xe3, 0xa8, 0xfc, 0xdc, 0xeb, 0x1a, 0xb2, 0x0d, 0x59, 0xe0,
    0x10, 0x28, 0x09, 0x5d, 0xb5, 0x23, 0x41, 0x85, 0x67, 0x50, 0xb7, 0xe5,
    0xfd, 0x97, 0x3f, 0x03, 0x52, 0x09, 0xf6, 0xe8, 0x20, 0x7f, 0xbb, 0xe3,
    0x59, 0x15, 0xd2, 0x6b, 0x9a, 0x5d, 0xd6, 0x7e, 0x9a, 0xe1, 0xac, 0xbf,
    0xc1, 0xd8, 0x17, 0x90, 0xdf, 0x4f, 0x46, 0x9b, 0x77, 0xa7, 0x2b, 0xbc,
    0xe7, 0x6b
])
aik_key: RSAPrivateKey = load_der_private_key(rsa_key, password=None, backend=default_backend())
assert isinstance(aik_key, RSAPrivateKey)

meta = {
    'version': 1,
    'mac': [1, 2, 3, 4, 5, 6],
    'sn': [0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01, 0x02, 0x10, 0x13, 0xee],
    'EK_hash': {
        'id': 1,
        'hash': [
            0xbb, 0x36, 0x3d, 0xff, 0xc0, 0x51, 0x2e, 0xf9,
            0xf6, 0xc8, 0xce, 0xae, 0x22, 0xe2, 0x41, 0x1c,
            0xdd, 0x22, 0x37, 0x0f, 0xec, 0x0d, 0x47, 0xf6,
            0xca, 0xa8, 0x1e, 0xb5, 0xd7, 0x35, 0x7e, 0xaf
        ]
    }
}

metadata_encoded = cbor.dumps(meta)
signature = aik_key.sign(
    metadata_encoded,
    padding.PKCS1v15(),
    hashes.SHA256()
)

with_sig = {
    'encoded_metadata': metadata_encoded,
    'signature': signature
}

hexdump(cbor.dumps(with_sig))
