# --- Chain Fork Simulation ---
def simulate_chain_fork():
    import os, time
    fork_point = os.urandom(32)
    header1 = BlockHeader(version=1, prev_block=fork_point, merkle_root=os.urandom(32), timestamp=int(time.time()), bits=0x1d00ffff, nonce=123)
    header2 = BlockHeader(version=1, prev_block=fork_point, merkle_root=os.urandom(32), timestamp=int(time.time())+1, bits=0x1d00ffff, nonce=456)
    block1 = BitcoinBlockPayload(header=header1, tx_count=0, transactions=[])
    block2 = BitcoinBlockPayload(header=header2, tx_count=0, transactions=[])
    return block1, block2

# --- Replay Attack Simulation ---
def simulate_replay_attack():
    import os
    tx = BitcoinTxPayload(
        version=1,
        tx_in_count=1,
        inputs=[TxInput(prev_txid=os.urandom(32), prev_index=0, scriptSig=b"reused", sequence=0xFFFFFFFF)],
        tx_out_count=1,
        outputs=[TxOutput(value=5000000000, scriptPubKey=b"script")],
        locktime=0
    )
    return tx

# --- Fake Block Broadcaster ---
def simulate_fake_block():
    import os, time
    bad_header = BlockHeader(
        version=9999,
        prev_block=os.urandom(32),
        merkle_root=b"invalid" * 4,
        timestamp=int(time.time()) + 999999,
        bits=0,
        nonce=0
    )
    fake_block = BitcoinBlockPayload(header=bad_header, tx_count=0, transactions=[])
    return fake_block
