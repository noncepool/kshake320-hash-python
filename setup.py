from distutils.core import setup, Extension

kshake320_hash = Extension('kshake320_hash',
    sources = [
        'kshake320hashmodule.cpp',
        'keccak/sha3.c',
        'keccak/KeccakHash.c',
        'keccak/KeccakRnd.c',
        'keccak/KeccakSponge.c',
        'keccak/KeccakF-1600/Optimized64/KeccakF-1600-opt64.c',
        'keccak/SnP/SnP-FBWL-default.c',
    ])

setup (name = 'kshake320_hash',
    version = '1.0',
    ext_modules = [kshake320_hash])
