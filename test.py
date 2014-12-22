def _test():       
    header_bin = binascii.unhexlify('0100000000000000cb43b0ec8ef4464f3d041493689274ee53741586acf0ad0b94b0d0986928165fd9823edff8000000917e5ee9f277da18cb60d7a3b3bf5cb3edf82a559f63de9ab5684405e382b69205139b983ea68fb20000000000000000000000000000000000000000ffff0026179cfb0343ff14000000000000000000')

    hash_bin = kshake320_hash.getPoWHash(header_bin)
    hash_int = uint320_from_str(hash_bin)
    print hash_int # 93738456153034120650016320092685904102166196045943475033169329722660916102004727975353821

    block_hash_hex = hash_bin[::-1].encode('hex_codec')    
    print block_hash_hex # 000000bc7c68fee7eec119a78c2aeb0a4a53721ac6f3ad130d3016cf6567c4ffd3bc0a4bd8b19ddd

def uint320_from_str(s):
    r = 0L
    t = struct.unpack("<IIIIIIIIII", s[:40])
    for i in xrange(10):
        r += t[i] << (i * 32)
    return r   

if __name__ == '__main__':
    import binascii
    import struct
    import kshake320_hash 
    _test()


