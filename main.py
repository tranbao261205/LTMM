"""Chạy các test vector và ghi toàn bộ trạng thái ra file văn bản."""
import argparse
import json
from pathlib import Path
import re
import des
import aes128

ROOT = Path(__file__).resolve().parent
ALGORITHMS = {'DES': des.crypt, 'AES-128': aes128.crypt}

def run_case(case, output, quiet=False):
    name = case['name']
    if not re.fullmatch(r'[a-zA-Z0-9_-]+', name):
        raise ValueError('Invalid test name')
    algorithm = ALGORITHMS[case['algorithm']]
    key, plain, expected = (bytes.fromhex(case[k]) for k in ('key','plaintext','ciphertext'))
    lines = []
    def log(line):
        lines.append(line)
        if not quiet:
            print(line)
    cipher = algorithm(plain, key, log=log)
    log('\n--- DECRYPT EXPECTED CIPHERTEXT ---')
    restored = algorithm(expected, key, decrypt=True, log=log)
    ok = cipher == expected and restored == plain
    log('\n--- VERIFICATION ---')
    log(f'Expected ciphertext: {expected.hex().upper()}')
    log(f'Actual ciphertext:   {cipher.hex().upper()}')
    log(f'Expected plaintext:  {plain.hex().upper()}')
    log(f'Actual plaintext:    {restored.hex().upper()}')
    log(f'Encryption: {"PASS" if cipher == expected else "FAIL"}')
    log(f'Decryption: {"PASS" if restored == plain else "FAIL"}')
    (output / f'{name}.txt').write_text('\n'.join(lines)+'\n', encoding='utf-8')
    return f'{name}: {"PASS" if ok else "FAIL"} | {cipher.hex().upper()}', ok

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--vectors', type=Path, default=ROOT/'vectors.json')
    p.add_argument('--algorithm', choices=['DES','AES-128','all'], default='all')
    p.add_argument('--output', type=Path, default=ROOT/'results')
    p.add_argument('--quiet', action='store_true', help='Only print summary; still save all states')
    a = p.parse_args()
    cases = json.loads(a.vectors.read_text(encoding='utf-8'))
    cases = [c for c in cases if a.algorithm == 'all' or c['algorithm'] == a.algorithm]
    if not cases:
        p.error('No matching test vectors')
    if len({c['name'] for c in cases}) != len(cases):
        p.error('Test names must be unique')
    a.output.mkdir(parents=True, exist_ok=True)
    results = [run_case(c,a.output,a.quiet) for c in cases]
    lines = [line for line,_ in results]
    lines.append(f'TOTAL: {sum(ok for _,ok in results)}/{len(results)} PASS')
    summary = '\n'.join(lines)+'\n'
    print(summary, end='')
    summary_name = 'summary.txt' if a.algorithm == 'all' else f'summary_{a.algorithm}.txt'
    (a.output/summary_name).write_text(summary,encoding='utf-8')
    return 0 if all(ok for _,ok in results) else 1

if __name__ == '__main__':
    raise SystemExit(main())
