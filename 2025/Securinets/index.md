# Lost Files
My G Los and I worked the Forensics challenges together. We're given an image file and a memory dump. First we load the image into FTK Imager

With a bit of digging around, we find `Documents and Settings\RagdollFan2005\Desktop` containing an encrypted file and an executable.
![[Pasted image 20251006115908.png]]
If we pull this executable and throw it into a decompiler, the program reads three things: `argv[1]`, the computer's name from the registry![[Pasted image 20251006120127.png]]
and a text file called `secret_part.txt` if it exists
![[Pasted image 20251006120234.png]]

Then it simply concatenates them into `<argv[1]>|<computer_name>|<contents of txt, or empty>` and takes the SHA256 of the string.
![[Pasted image 20251006120616.png]]

This result is the key, and the IV is the first 16 bytes of the key in the 256-aes-cbc encryption.
![[Pasted image 20251006121924.png]]
Now the goal is to find the passphrase `argv[1]` used, the computer name, and the contents of `secret_part.txt`

First we can dry run the program, with the command
```bash
PW="hello"
COMPUTER=hostname
TEXTFILE="hi"
KEY=$(echo '$PW|$TEXTFILE|$SECRET' | sha256sum | awk '{print $1}')
IV=$(echo $KEY | cut -c1-32)
```
```bash
openssl enc -d -aes-256-cbc -K $KEY -iv $IV -in to_encrypt.txt -out test.txt
```
and compare it with the `locker_sim.exe`
```bash
.\locker_sim.exe pass
```

Our idea was to find them all in the memory dump, however, we only found the passphrase and the computer name
```bash
vol.py -f mem.vmem --profile=WinXPSP3x86 consoles
```
```
...
C:\Documents and Settings\RagdollFan2005\Desktop>locker_sim.exe hmmisitreallyts ************************************************** ConsoleProcess: csrss.exe Pid: 600 Console: 0x1044560 CommandHistorySize: 50 HistoryBufferCount: 2 HistoryBufferMax: 4 OriginalTitle: ?OystemRoot%\system32\cmd.exe
...
```
```bash
vol -f mem.vmem windows.registry.printkey --offset 0xe1035b60 --key 
```
```
...
2019-10-01 06:35:33.000000 UTC 0xe1035b60 REG_SZ \Device\HarddiskVolume1\WINDOWS\system32\config\system\ControlSet001\Control\ComputerName\ComputerName ComputerName "RAGDOLLF-F9AC5A" False
```

After a long search, the secret part was not in the memory dump. We used the best tool available:
```bash
strings mem.vmem
```
and grepped for `secret_part.txt`. Notice how in the program instructions:
![[Pasted image 20251006123530.png]]
The file is deleted afterwards.

The strings output mentioned RECYCLER and DC1.txt quite often
![[Pasted image 20251006123708.png]]
And noticing that file contents can get recycled as "DC"
https://digitalresidue.blogspot.com/2013/06/when-windows-deletes-it.html

we searched the bin, and what do you know? There's a `DC1.txt` with the content, `sigmadroid`
![[Pasted image 20251006123941.png]]

Plug this into the same commands, or this short script:
```python
import hashlib
argv1     = b"hmmisitreallyts"
comp      = b"RAGDOLLF-F9AC5A"
secret    = b"sigmadroid"
S = argv1 + b"|" + comp + b"|" + (secret if secret else b"")
K = hashlib.sha256(S).digest()
print("K =", K.hex())
print("IV=", K[:16].hex())

print(f"openssl enc -d -aes-256-cbc -K {K.hex()} -iv {K[:16].hex()} -in to_encrypt.txt.enc -out recovered.txt")
```

and run it in the directory with the encrypted file, to find the output:
```
Vm14U1MxWXlSblJWYkd4VVltdEtjRmxzV2xwa01XdzJWR3BDYkdKSGREWlZNakUwV1ZaYU5sVnViRnBOYWtaWVdXMHhSMWRXVW5GUmJYQnBZbGhTTlZkWGVHdFpWVEZIVVdwYVVGWkhjems9
```

Which looks like base 64, and if you decrypt it:

```
VmxSS1YyRnRVbGxUYmtKcFlsWlpkMWw2VGpCbGJHdDZVMjE0WVZaNlVubFpNakZYWW0xR1dWUnFRbXBpYlhSNVdXeGtZVTFHUWpaUFZHczk=
```

Which looks like base 64, and if you decrypt it:

```
VTJWamRYSnBibVYwYzN0elkzSmxaVzRyY21WbmFYTjBjbmtyYldaMFB6OTk=
```

Which looks like base 64, and if you decrypt it:

```
U2VjdXJpbmV0c3tzY3JlZW4rcmVnaXN0cnkrbWZ0Pz99
```

Which looks like base 64, and if you decrypt it:

```
Securinets{screen+registry+mft??}
```

Which looks like the flag!

# Recovery
This challenge was out of our domain. We have two things: a file system, and a `pcapng` file. First, we look at the filesystem provided. It's easy to notice that pretty much all the files are a jumbled mess, an obvious ransomware attack. For example, this is `ip.txt`
![[Pasted image 20251006125902.png]]
Which is definitely not a txt file.

There are some files that are unencrypted though: `IMPORTANT_NOTICE.txt` and `powershell_history.txt`. The former reinforces the idea of it being ransomware, as it says to pay to a given bitcoin address
```
*** IMPORTANT NOTICE ***

Payment of 0.1Btc must be made in Bitcoin to the following wallet: bc1qa5wkgaew2dkv56kfvj49j0av5nml45x9ek9hz6

After payment, you will receive a decryption tool and instructions.

You have 72 hours to comply.
```
But the latter gives evidence of a github repo being used, at https://github.com/youssefnoob003/dns100-free.

Looking at the previous commits, we can see that `dns_server.py` is tainted with code to perform a download by using the same technique as a DNS exfiltration attack. It downloads a payload from around 678 chunks, and deobfuscates them by decoding the base32 string and XORing them with a single-byte key. We can find all of these as UDP streams in the `pcapng` file. Simply filter `udp.port == 53 and frame contains "meow"` 

To reconstruct the files, we split the query into \[B\]BASE32.CHUNK.meow, manually decoded every base32 string, removed the first byte (B) and used the second byte as the key.

Example: `BEBWXVMBAEMQCAIBEEAQCBX67EAQJQIBAEAQCAIBAMAQCAIBAEAQCAIBAEAQCAIBAEA.0.meow`
We would decode the string, get the one-byte key (`0x20`) from the byte (E) next to B.

Then we simply XOR the entire result with 0x20 and with all the chunks arranged, we construct a malware payload.

We asked GPT to script this, because we can:
```python
import struct, base64, hashlib, os, sys, ipaddress, re, argparse, json
from typing import Dict, Tuple, List

def read_pcapng_packets(path):
    with open(path, "rb") as f:
        data = f.read()
    off = 0
    endian = "<"
    if len(data) < 12 or struct.unpack_from("<I", data, 0)[0] != 0x0A0D0D0A:
        if len(data) < 12 or struct.unpack_from(">I", data, 0)[0] != 0x0A0D0D0A:
            raise ValueError("Not a pcapng file")
        endian = ">"
    # Determine endianness
    bom = struct.unpack_from(endian + "I", data, 8)[0]
    if bom == 0x4D3C2B1A:
        endian = ">" if endian == "<" else "<"
    elif bom != 0x1A2B3C4D:
        raise ValueError("Invalid byte-order magic in SHB")
    while off + 12 <= len(data):
        try:
            btype, blen = struct.unpack_from(endian + "II", data, off)
        except struct.error:
            break
        if blen < 12 or off + blen > len(data):
            break
        body = data[off+8:off+blen-4]
        if btype == 0x00000006:  # Enhanced Packet Block
            if len(body) >= 20:
                _, _, _, cap_len, _ = struct.unpack_from(endian + "IIIII", body, 0)
                pkt = body[20:20+cap_len]
                yield pkt
        elif btype == 0x00000003:  # Simple Packet Block
            if len(body) >= 4:
                pkt = body[4:]
                yield pkt
        off += blen

def parse_ipv4_udp(pkt):
    # Ethernet
    if len(pkt) < 14: return None
    eth_type = struct.unpack_from("!H", pkt, 12)[0]
    if eth_type != 0x0800: return None
    ip_off = 14
    if len(pkt) < ip_off + 20: return None
    ver_ihl = pkt[ip_off]
    if (ver_ihl >> 4) != 4: return None
    ihl = (ver_ihl & 0x0F) * 4
    if len(pkt) < ip_off + ihl: return None
    proto = pkt[ip_off + 9]
    if proto != 17: return None  # UDP
    src_ip = ".".join(str(b) for b in pkt[ip_off+12:ip_off+16])
    dst_ip = ".".join(str(b) for b in pkt[ip_off+16:ip_off+20])
    udp_off = ip_off + ihl
    if len(pkt) < udp_off + 8: return None
    src_port, dst_port, ulen = struct.unpack_from("!HHH", pkt, udp_off)
    data = pkt[udp_off+8:udp_off+ulen]
    return (src_ip, src_port, dst_ip, dst_port, data)

def dns_qname_labels(msg, offset=12):
    labels = []
    seen = set()
    def walk(pos, depth=0):
        nonlocal labels
        if depth > 15: return
        while True:
            if pos >= len(msg): return
            l = msg[pos]; pos += 1
            if l == 0: return
            if (l & 0xC0) == 0xC0:
                if pos >= len(msg): return
                ptr = ((l & 0x3F) << 8) | msg[pos]; pos += 1
                if ptr in seen: return
                seen.add(ptr)
                walk(ptr, depth+1); return
            if pos + l > len(msg): return
            labels.append(msg[pos:pos+l].decode("ascii", "ignore").lower())
            pos += l
    walk(offset)
    return labels

def flow_key(src_ip, src_port, dst_ip, dst_port):
    if dst_port == 53:
        return (src_ip, src_port, dst_ip, dst_port)
    if src_port == 53:
        return (dst_ip, dst_port, src_ip, src_port)
    a = (src_ip, src_port); b = (dst_ip, dst_port)
    return (a, b) if a <= b else (b, a)

def safe_b32decode(s):
    s = s.upper()
    s += "=" * ((8 - (len(s) % 8)) % 8)
    return base64.b32decode(s)

def detect_ext(b):
    if b[:2] == b"MZ": return ".exe"
    if b[:4] == b"\x7fELF": return ".elf"
    if b[:4] == b"\x89PNG": return ".png"
    if b[:4] == b"%PDF": return ".pdf"
    return ".bin"

def extract_streams(pcap_path, suffix="meow"):
    flows = {}
    for pkt in read_pcapng_packets(pcap_path):
        parsed = parse_ipv4_udp(pkt)
        if not parsed: continue
        s_ip, s_pt, d_ip, d_pt, udp_payload = parsed
        if s_pt != 53 and d_pt != 53: 
            continue
        if len(udp_payload) < 12: 
            continue
        qd = struct.unpack_from("!H", udp_payload, 4)[0]
        if qd < 1: 
            continue
        labels = dns_qname_labels(udp_payload, 12)
        if not labels: 
            continue
        if labels[-1] != suffix:
            continue
        key = flow_key(s_ip, s_pt, d_ip, d_pt)
        flows.setdefault(key, []).append(labels)
    return flows

def decode_labels_to_bytes(labels_list):
    chunks = {}
    keys_seen = set()
    for labels in labels_list:
        if len(labels) < 3: 
            continue
        b32lab = labels[0]
        try:
            idx = int(labels[1])
        except ValueError:
            continue
        try:
            raw = safe_b32decode(b32lab)
        except Exception:
            continue
        if not raw or len(raw) < 2:
            continue
        key = raw[0]
        keys_seen.add(key)
        payload = bytes(b ^ key for b in raw[1:])
        chunks[idx] = payload
    if not chunks:
        return None, None, None
    ordered = b"".join(chunks[i] for i in sorted(chunks.keys()))
    return ordered, sorted(chunks.keys()), sorted(keys_seen)

def write_output(base_outdir, flow, blob):
    c_ip, c_pt, s_ip, s_pt = flow
    outdir = os.path.join(base_outdir, f"{c_ip}_{c_pt}_to_{s_ip}_{s_pt}")
    os.makedirs(outdir, exist_ok=True)
    sha256 = hashlib.sha256(blob).hexdigest()
    ext = detect_ext(blob)
    out_path = os.path.join(outdir, f"recovered{ext}")
    with open(out_path, "wb") as f:
        f.write(blob)
    meta = {
        "sha256": sha256,
        "size": len(blob),
        "flow": {"client_ip": c_ip, "client_port": c_pt, "server_ip": s_ip, "server_port": s_pt},
        "output": os.path.basename(out_path),
    }
    with open(os.path.join(outdir, "meta.json"), "w") as f:
        json.dump(meta, f, indent=2)
    return out_path, sha256, outdir

def main():
    ap = argparse.ArgumentParser(description="Decode DNS exfil streams with <key+b32>.<idx>.*.<suffix> format.")
    ap.add_argument("--pcap", required=True, help="Path to pcapng file")
    ap.add_argument("--suffix", default="meow", help="Expected domain suffix (default: meow)")
    ap.add_argument("--list-streams", action="store_true", help="List detected UDP streams carrying exfil labels")
    ap.add_argument("--flow", default=None, help='Decode only this flow. Format: client_ip:client_port>server_ip:server_port')
    ap.add_argument("--outdir", default="dns_exfil_out", help="Output directory")
    args = ap.parse_args()

    flows = extract_streams(args.pcap, suffix=args.suffix)

    if args.list_streams:
        if not flows:
            print("No candidate streams found.")
            return 0
        print("Streams:")
        for k, labels in flows.items():
            c_ip, c_pt, s_ip, s_pt = k
            print(f"{c_ip}:{c_pt}>{s_ip}:{s_pt}  packets={len(labels)}")
        return 0

    to_decode = {}
    if args.flow:
        import re
        m = re.match(r"^([^:]+):(\d+)>([^:]+):(\d+)$", args.flow.strip())
        if not m:
            print("Invalid --flow format. Use client_ip:client_port>server_ip:server_port", file=sys.stderr)
            return 2
        c_ip, c_pt, s_ip, s_pt = m.group(1), int(m.group(2)), m.group(3), int(m.group(4))
        key = (c_ip, c_pt, s_ip, s_pt)
        if key not in flows:
            print("Specified flow not found among candidates. Try --list-streams.", file=sys.stderr)
            return 3
        to_decode[key] = flows[key]
    else:
        to_decode = flows

    if not to_decode:
        print("No streams to decode.")
        return 0

    os.makedirs(args.outdir, exist_ok=True)
    any_success = False
    for flow, labels in to_decode.items():
        blob, indices, keys = decode_labels_to_bytes(labels)
        c_ip, c_pt, s_ip, s_pt = flow
        if blob is None:
            print(f"[FAIL] {c_ip}:{c_pt}>{s_ip}:{s_pt}  decoded=0")
            continue
        out_path, sha256, odir = write_output(args.outdir, flow, blob)
        print(f"[OK] {c_ip}:{c_pt}>{s_ip}:{s_pt}  chunks={len(indices)}  idx=[{min(indices)}..{max(indices)}]  keys={[hex(k) for k in keys]}  size={len(blob)}  sha256={sha256}  out={out_path}")
        any_success = True
    return 0 if any_success else 1

if __name__ == "__main__":
    sys.exit(main())
```
Run with one of the streams
```bash
python3 decode_dns_exfil.py --pcap cap.pcapng --flow "192.168.85.175:37212>10.0.0.2:53"
```

And we find that all of the streams are identical files.

Next, we notice that the malware is staged, and that it's still packed in the payload
```bash
file recovered.exe1
```
```
virusus/recovered.exe1: PE32 executable (console) Intel 80386 (stripped to external PDB), for MS Windows, UPX compressed
```

Confirm it's packed:
```bash
upx-ucl -l recovered.exe1
```
![[Pasted image 20251006141813.png]]
Unpack it:
```bash
upx-ucl -d recovered.exe1
```

And throw it in for some code analysis. We can immediately see the strings which match the notice that we saw earlier.
![[Pasted image 20251006140509.png]]

We also find the key ![[Pasted image 20251006141934.png]]
`evilsecretcodeforevilsecretencryption`

![[Pasted image 20251006145210.png]]

The code will 
- Find path length by scanning to the NUL. Sets `i` to 0xFFFFFFFF then walks bytes until `*edi==0`.
- Fold each path byte into a 32-bit accumulator `edx` using 8-bit rotates by `(i_1&3)<<3`. This is a crude little-endian mixer.    
- XOR in a 0x25-word built-in table `data_40b200` (the secret key we got) with the same 0/8/16/24-bit shifts. This further perturbs `edx`.    
- Treat `edx` as the PRNG state. For each output byte, update `edx = edx*0x19660D + 0x3C6EF35F` (LCG), then spill the low byte(s) of `edx` into the output buffer until `arg3` bytes are produced.
Result: deterministic keystream per path and length.
![[Pasted image 20251006145822.png]]
Then the malware
- Read the whole file into memory. Generate a keystream of the same length using the path as seed, using the previous function.
- XOR each byte: `_Buffer[i] ^= keystream[i]`
      
Since XOR is symmetric. Running it again on the same path restores the original bytes.

![[Pasted image 20251006150058.png]]
Lastly, it does a directory walk and performs the encryption recursively, encrypting every file
.
And the python payload for decrypting files:
```python
import argparse
import os
from typing import ByteString


HARD_CODED_KEY = b"evilsecretcodeforevilsecretencryption"  # 37 bytes


def to_signed_byte(value: int) -> int:
    return value - 256 if value >= 128 else value


def derive_initial_value(filename: str, gEncryptionKey: ByteString) -> int:
    """Derive the initial seed value from filename and encryption key (same as C logic)."""
    value = 0
    # Mix filename bytes (signed)
    for index, b in enumerate(filename.encode("utf-8", errors="ignore")):
        shift = 8 * (index & 3)
        value ^= (to_signed_byte(b) & 0xFFFFFFFF) << shift
        value &= 0xFFFFFFFF
    # Mix key bytes (first 37, signed)
    for i in range(37):
        kb = gEncryptionKey[i]
        shift = 8 * (i & 3)
        value ^= (to_signed_byte(kb) & 0xFFFFFFFF) << shift
        value &= 0xFFFFFFFF

    return value & 0xFFFFFFFF


def generate_keystream(seed: int, length: int) -> bytes:
    a = 0x19660D
    c = 0x3C6EF35F
    value = seed & 0xFFFFFFFF
    out = bytearray(length)
    for i in range(length):
        value = (a * value + c) & 0xFFFFFFFF
        out[i] = value & 0xFF
    return bytes(out)


def decrypt(filename: str, ciphertext: bytes, gEncryptionKey: ByteString) -> bytes:
    seed = derive_initial_value(filename, gEncryptionKey)
    ks = generate_keystream(seed, len(ciphertext))
    return bytes(c ^ k for c, k in zip(ciphertext, ks))


def main() -> None:
    parser = argparse.ArgumentParser(description="Decrypt file encrypted by payload35 XOR PRNG.")
    parser.add_argument("input", help="Path to encrypted file")
    parser.add_argument("output", help="Path to write decrypted output")
    parser.add_argument("seed_string", help="Seed filename string used during encryption (e.g., C\\\\Users\\\\Alice\\\\Pictures\\\\sillyflag.png)")
    args = parser.parse_args()

    with open(args.input, "rb") as f:
        data = f.read()
    plain = decrypt(args.seed_string, data, HARD_CODED_KEY)
    with open(args.output, "wb") as f:
        f.write(plain)
    print(f"Decryption complete -> {args.output}")


if __name__ == "__main__":
    main()
```
![[Pasted image 20251006142120.png]]
Credits to Vmpr0be for reversing the code and c15c01337 for the decryption algorithm.