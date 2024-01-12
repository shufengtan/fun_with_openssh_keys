# This code is almost identical to https://ed25519.cr.yp.to/python/sign.py
# with trivial changes to make it work on python3

import ed25519
import binascii
import requests
import time

input_text = requests.get('https://ed25519.cr.yp.to/python/sign.input').text

# fields on each input line: sk, pk, m, sm
# each field hex
# each field colon-terminated
# sk includes pk at end
# sm includes m at end
with open('test.out', 'w') as wfo:
    for ix, line in enumerate(input_text.splitlines()):
        t0 = time.perf_counter()
        x = line.split(':')
        sk = binascii.unhexlify(x[0][0:64])
        pk = ed25519.publickey(sk)
        m = binascii.unhexlify(x[2])
        s = ed25519.signature(m,sk,pk)
        ed25519.checkvalid(s,m,pk)
        forgedsuccess = 0
        if len(m) == 0:
            forgedm = "x"
        else:
            forgedmlen = len(m)
            forgedm = bytes([(m[i]+(i==forgedmlen-1)) % 256 for i in range(forgedmlen)])
            assert m[:-1]==forgedm[:-1]
        try:
            ed25519.checkvalid(s,forgedm,pk)
            forgedsuccess = 1
        except:
            pass
        et = time.perf_counter() - t0
        wfo.write(f'Line {ix} len(m): {len(m)} ok. et: {et}\n')
        wfo.flush()
        assert not forgedsuccess
        assert bytes(x[0], encoding='ascii') == binascii.hexlify(sk + pk)
        assert bytes(x[1], encoding='ascii') == binascii.hexlify(pk)
        assert bytes(x[3], encoding='ascii') == binascii.hexlify(s + m)
