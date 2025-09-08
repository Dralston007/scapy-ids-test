from scapy.all import *
import time
import struct

# Define custom fields BEFORE the main classes

class MagicField(StrFixedLenField):
    VALID_MAGICS = {
        b"\xf9\xbe\xb4\xd9": "mainnet",
        b"\x0b\x11\x09\x07": "testnet",
        b"\xfa\xbf\xb5\xda": "regtest"
    }

    def __init__(self, name, default):
        super().__init__(name, default, length=4)

    def any2i(self, pkt, val):
        # val is the raw bytes to be parsed or assigned
        if val not in self.VALID_MAGICS:
            raise ValueError(f"Invalid magic bytes: {val.hex()}")
        return val

class CommandField(StrFixedLenField):
    def __init__(self, name, default):
        StrFixedLenField.__init__(self, name, default, length=12)

    def i2repr(self, pkt, x):
        return repr(x.rstrip(b'\x00'))

class VarIntField(Field):
    def __init__(self, name, default=0):
        super().__init__(name, default, fmt="")

    def i2m(self, pkt, val):
        if val < 0xfd:
            return struct.pack("<B", val)
        elif val <= 0xffff:
            return b"\xfd" + struct.pack("<H", val)
        elif val <= 0xffffffff:
            return b"\xfe" + struct.pack("<I", val)
        else:
            return b"\xff" + struct.pack("<Q", val)

    def m2i(self, pkt, val):
        # This method should only return the parsed value
        # getfield handles the remaining bytes
        if not val:
            return 0
        prefix = val[0]
        if prefix < 0xfd:
            return prefix
        elif prefix == 0xfd:
            return struct.unpack("<H", val[1:3])[0]
        elif prefix == 0xfe:
            return struct.unpack("<I", val[1:5])[0]
        else:
            return struct.unpack("<Q", val[1:9])[0]

    def getfield(self, pkt, s):
        if not s:
            return b"", 0
        prefix = s[0]
        if prefix < 0xfd:
            return s[1:], prefix
        elif prefix == 0xfd:
            return s[3:], struct.unpack("<H", s[1:3])[0]
        elif prefix == 0xfe:
            return s[5:], struct.unpack("<I", s[1:5])[0]
        else:
            return s[9:], struct.unpack("<Q", s[1:9])[0]

    def addfield(self, pkt, s, val):
        return s + self.i2m(pkt, val)

class VarStrField(Field):
    def __init__(self, name, default=b""):
        super().__init__(name, default, fmt="")

    def getfield(self, pkt, s):
        length, s = VarIntField("length").getfield(pkt, s)
        val = s[:length]
        return s[length:], val

    def addfield(self, pkt, s, val):
        length_field = VarIntField("length")
        return s + length_field.i2m(pkt, len(val)) + val

# --- Bitcoin P2P Base Message ---
class BitcoinMessage(Packet):
    name = "BitcoinMessage"
    fields_desc = [
        MagicField("magic", b"\xf9\xbe\xb4\xd9"),
        CommandField("command", "version"),
        IntField("length", 0),
        StrFixedLenField("checksum", b"\x00" * 4, length=4),
        StrLenField("payload", b"", length_from=lambda pkt: pkt.length)
    ]
    
    def guess_payload_class(self, payload):
        cmd = self.command.strip(b'\x00').decode('ascii')
        dispatch = {
            "tx": BitcoinTxPayload,
            "block": BitcoinBlockPayload,
            "version": BitcoinVersionPayload,
        }
        return dispatch.get(cmd, Raw)

class NetworkAddress(Packet):
    fields_desc = [
        LongField("services", 0),
        StrFixedLenField("ip", b"\x00"*16, length=16),
        ShortField("port", 0)
    ]

class BitcoinVersionPayload(Packet):
    name = "BitcoinVersionPayload"
    fields_desc = [
        IntField("version", 70015),
        LongField("services", 0),
        LongField("timestamp", 0),
        PacketField("addr_recv", NetworkAddress()),
        PacketField("addr_from", NetworkAddress()),
        LongField("nonce", 0),
        VarStrField("user_agent"),
        IntField("start_height", 0),
        ByteField("relay", 0),
    ]

# --- Transaction Input ---
class TxInput(Packet):
    fields_desc = [
        StrFixedLenField("prev_txid", b"\x00"*32, length=32),
        IntField("prev_index", 0),
        VarStrField("scriptSig"),
        IntField("sequence", 0xFFFFFFFF),
    ]

# --- Transaction Output ---
class TxOutput(Packet):
    fields_desc = [
        LongField("value", 0),  # 8 bytes, little-endian
        VarStrField("scriptPubKey"),
    ]

# --- Full Transaction Payload ---
class BitcoinTxPayload(Packet):
    name = "BitcoinTxPayload"
    fields_desc = [
        IntField("version", 1),
        VarIntField("tx_in_count"),
        PacketListField("inputs", [], TxInput, count_from=lambda pkt: pkt.tx_in_count),
        VarIntField("tx_out_count"),
        PacketListField("outputs", [], TxOutput, count_from=lambda pkt: pkt.tx_out_count),
        IntField("locktime", 0),
    ]

# --- Block Header ---
class BlockHeader(Packet):
    fields_desc = [
        IntField("version", 0),
        StrFixedLenField("prev_block", b"\x00"*32, length=32),
        StrFixedLenField("merkle_root", b"\x00"*32, length=32),
        IntField("timestamp", 0),
        IntField("bits", 0),
        IntField("nonce", 0),
    ]

# --- Full Block Payload ---
class BitcoinBlockPayload(Packet):
    name = "BitcoinBlockPayload"
    fields_desc = [
        PacketField("header", BlockHeader, BlockHeader),
        VarIntField("tx_count"),
        PacketListField("transactions", [], BitcoinTxPayload, count_from=lambda pkt: pkt.tx_count),
    ]