# CTF Write-ups — exploitcartel

> Reverse engineering write-ups from various CTF competitions.  
> All flags recovered via **static analysis only** (no dynamic execution required except where noted).

---

## Challenges

| # | Challenge | Points | Category | Flag |
|---|-----------|--------|----------|------|
| 1 | [Big Gete Star](./challenge1/) | 200 | Rev / XOR | `flag{xor_baby}` |
| 2 | [XO XO OR?](./challenge2/) | 200 | Rev / XOR | `Fl4g{4r3_y0u_4n_X0R_g0d?}` |
| 3 | [Master of Disaster](./challenge3/) | 200 | Rev / XOR | `FLAG{n0_m0r3_str1ngs}` |
| 4 | [Ransomware Vibes](./challenge4/) | 250 | Rev / .NET / AES | `FLAG{AES_m4kes_RE_good}` |
| 5 | [The Trainer's Binary](./challenge5-trainer/) | 300 | Rev / Multi-layer | `flag{42Tirana-Well_Done}` |

**Total: 1150 pts**

---

## Techniques Covered

- Single-byte XOR decryption from hardcoded immediates
- ELF `.data` section XOR flag recovery
- .NET metadata `#US` heap extraction (AES key/IV/ciphertext)
- AES-128-CBC decryption with PKCS#7 unpadding
- ELF anti-debug via `ptrace(PTRACE_TRACEME)` bypass
- System V AMD64 ABI argument order (rdi, rsi, rdx, rcx, r8, r9)
- Multi-stage decode: hex → XOR (rolling key) → base64
- RIP-relative addressing to map `.rodata` segment offsets

---

## Tools Used

- `file`, `strings`, `xxd` — initial triage
- Python 3 — all solve scripts
- `cryptography` Python library — AES decryption
- Hex editor / disassembler — static analysis

---

## Structure

```
ctf-writeups/
├── README.md                  ← this file
├── challenge1/
│   └── README.md              ← Big Gete Star (ELF XOR)
├── challenge2/
│   └── README.md              ← XO XO OR? (PE XOR)
├── challenge3/
│   └── README.md              ← Master of Disaster (PE XOR)
├── challenge4/
│   └── README.md              ← Ransomware Vibes (.NET AES)
└── challenge5-trainer/
    └── README.md              ← The Trainer's Binary (Multi-layer)
```
