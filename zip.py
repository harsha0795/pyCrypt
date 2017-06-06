import zlib

def compress(message):
    ''' Apply ZIP compression Algorithm '''
    return zlib.compress(message)

def decompress(decompstr):
    ''' Apply ZIP decompression Algorithm '''
    return zlib.decompress(decompstr)

