import json
from pathlib import Path
import unittest
import random
import des
import aes128 as aes

class TestAlgorithms(unittest.TestCase):
    def test_known_answers(self):
        vectors = json.loads((Path(__file__).resolve().parents[1]/'vectors.json').read_text())
        for v in vectors:
            with self.subTest(v=v['name']):
                f = des.crypt if v['algorithm']=='DES' else aes.crypt
                p,k,c = (bytes.fromhex(v[x]) for x in ('plaintext','key','ciphertext'))
                self.assertEqual(f(p,k),c)
                self.assertEqual(f(c,k,True),p)

    def test_des_round_1(self):
        key = 0x133457799BBCDFF1
        self.assertEqual(des.permute(0x0123456789ABCDEF,des.IP,64),0xCC00CCFFF0AAF0AA)
        keys = des.key_schedule(key)
        self.assertEqual(keys[0],0x1B02EFFC7072)
        self.assertEqual(keys[-1],0xCB3D8B0E17F5)
        trace=[]
        self.assertEqual(des.feistel(0xF0AAF0AA,keys[0],trace.append),0x234AA9BB)
        for line in ['  E(R)       = 7A15557A1555','  E(R) XOR K = 6117BA866527','  S-box      = 5C82B597']:
            self.assertIn(line,trace)
        self.assertEqual(0xCC00CCFF ^ 0x234AA9BB,0xEF4A6544)

    def test_aes_round_1(self):
        p = bytes.fromhex('00112233445566778899AABBCCDDEEFF')
        k = bytes.fromhex('000102030405060708090A0B0C0D0E0F')
        keys = aes.key_expansion(k)
        self.assertEqual(aes.hx(keys[1]),'D6AA74FDD2AF72FADAA678F1D6AB76FE')
        self.assertEqual(aes.hx(keys[10]),'13111D7FE3944A17F307A78B4D2B30C5')
        s = aes.add_round_key(p,keys[0]); self.assertEqual(aes.hx(s),'00102030405060708090A0B0C0D0E0F0')
        s = aes.sub_bytes(s); self.assertEqual(aes.hx(s),'63CAB7040953D051CD60E0E7BA70E18C')
        s = aes.shift_rows(s); self.assertEqual(aes.hx(s),'6353E08C0960E104CD70B751BACAD0E7')
        s = aes.mix_columns(s); self.assertEqual(aes.hx(s),'5F72641557F5BC92F7BE3B291DB9F91A')
        s = aes.add_round_key(s,keys[1]); self.assertEqual(aes.hx(s),'89D810E8855ACE682D1843D8CB128FE4')

    def test_aes_primitives(self):
        self.assertEqual(aes.gf_mul(0x57,0x13),0xFE)
        self.assertEqual(aes.SBOX[0x53],0xED)
        for x in range(256):
            self.assertEqual(aes.INV_SBOX[aes.SBOX[x]],x)
        state = list(range(16))
        self.assertEqual(aes.shift_rows(aes.shift_rows(state),True),state)
        self.assertEqual(aes.mix_columns(aes.mix_columns(state),True),state)

    def test_round_trip(self):
        rng = random.Random(4230)
        for f,n in ((des.crypt,8),(aes.crypt,16)):
            for _ in range(20):
                p,k = (bytes(rng.randrange(256) for _ in range(n)) for _ in range(2))
                self.assertEqual(f(f(p,k),k,True),p)

    def test_invalid_length(self):
        for f,n in ((des.crypt,8),(aes.crypt,16)):
            with self.assertRaises(ValueError): f(bytes(n-1),bytes(n))
            with self.assertRaises(ValueError): f(bytes(n),bytes(n-1))

if __name__=='__main__':
    unittest.main()
