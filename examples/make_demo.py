"""Non-executable synthetic PE metadata fixture, not a functional executable."""
from pathlib import Path
import struct
b = bytearray(1024)
def put16(offset, value): struct.pack_into('<H', b, offset, value)
def put32(offset, value): struct.pack_into('<I', b, offset, value)
b[:2] = b'MZ'; put32(60, 128); b[128:132] = b'PE\0\0'
put16(132, 0x8664); put16(134, 1); put16(148, 240); put16(152, 0x20b)
put16(222, 0x160); put32(260, 16); put32(304, 0x1000); put32(308, 16)
b[392:397] = b'.data'; put32(400, 512); put32(404, 0x1000)
put32(408, 512); put32(412, 512); put32(428, 0x40000040)
Path(__file__).with_name('synthetic.pe').write_bytes(b)
print('Synthetic metadata fixture created; do not execute it.')
