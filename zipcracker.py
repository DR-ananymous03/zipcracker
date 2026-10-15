#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════════════╗
║              ZIP Cracker — Interactive Simple Edition                    ║
║                                                                          ║
║  Run:   python zipcracker.py                                             ║
║                                                                          ║
║  Just answer the questions — no arguments to remember.                   ║
╚══════════════════════════════════════════════════════════════════════════╝
"""

import os
import sys
import time
import json
import signal
import ctypes
import hashlib
import tempfile
import subprocess
import threading
import multiprocessing as mp
from concurrent.futures import ProcessPoolExecutor, wait, FIRST_COMPLETED
from collections import deque

# ═══════════════════════════════════════════════════════════════════════════
#  Colors & Helpers
# ═══════════════════════════════════════════════════════════════════════════

class C:
    RESET="\033[0m"; BOLD="\033[1m"; RED="\033[91m"; GREEN="\033[92m"
    YELLOW="\033[93m"; BLUE="\033[94m"; MAGENTA="\033[95m"
    CYAN="\033[96m"; GRAY="\033[90m"


def _color_ok():
    try:
        return sys.stdout.isatty()
    except Exception:
        return False


def c(text, color):
    return f"{color}{text}{C.RESET}" if _color_ok() else text


def human_speed(s):
    if s >= 1e9: return f"{s/1e9:.2f}G/s"
    if s >= 1e6: return f"{s/1e6:.2f}M/s"
    if s >= 1e3: return f"{s/1e3:.2f}K/s"
    return f"{s:.0f}/s"


def human_time(s):
    if s < 60: return f"{s:.1f}s"
    if s < 3600: return f"{s/60:.1f}m"
    if s < 86400: return f"{s/3600:.1f}h"
    return f"{s/86400:.1f}d"


def human_num(n):
    return f"{n:,}"


def human_size(b):
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if b < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} PB"


def banner():
    art = r"""
   ______ _____ _____    _____                _             
  |___  /_   _|  __ \  / ____|              | |            
     / /  | | | |__) || |     _ __ __ _  ___| | _____ _ __ 
    / /   | | |  ___/ | |    | '__/ _` |/ __| |/ / _ \ '__|
   / /__ _| |_| |     | |____| | | (_| | (__|   <  __/ |   
  /_____|_____|_|      \_____|_|  \__,_|\___|_|\_\___|_|   
             Simple Edition — Interactive
    """
    print(c(art, C.CYAN + C.BOLD))


def line(char="─", n=64):
    print(c(char * n, C.GRAY))


def pause_and_exit(msg="Press Enter to exit..."):
    if os.name == "nt" or sys.stdin.isatty():
        try:
            input(c(f"\n{msg}", C.GRAY))
        except Exception:
            pass


# ═══════════════════════════════════════════════════════════════════════════
#  Native C Engines
# ═══════════════════════════════════════════════════════════════════════════

_C_ENGINES = r"""
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

typedef struct { uint32_t keys[3]; } ZipKeys;
static inline void zk_update(ZipKeys *k, uint8_t ch) {
    k->keys[0] = (k->keys[0] ^ ch) * 134775813u + 1u;
    k->keys[1] = (k->keys[1] + (k->keys[0] >> 24)) * 134775813u + 1u;
    k->keys[2] = (k->keys[2] + (k->keys[1] >> 24)) * 134775813u + 1u;
}
static inline uint8_t zk_decrypt(ZipKeys *k) {
    uint32_t t = k->keys[2] | 2u;
    return (uint8_t)((t * (t ^ 1u)) >> 8);
}
static void zk_init(ZipKeys *k, const uint8_t *p, int n) {
    k->keys[0]=0x12345678u; k->keys[1]=0x23456789u; k->keys[2]=0x34567890u;
    for (int i = 0; i < n; i++) zk_update(k, p[i]);
}
static int zk_verify(const uint8_t *p, int n, const uint8_t *cb, uint8_t ck) {
    ZipKeys k; zk_init(&k, p, n);
    uint8_t last = 0;
    for (int i = 0; i < 12; i++) {
        uint8_t ch = cb[i] ^ zk_decrypt(&k);
        last = ch; zk_update(&k, ch);
    }
    return (last == ck) ? 1 : 0;
}
int zipcrypto_crack_batch(const char *pd, const int *pl, int n,
                          const uint8_t *cb, uint8_t ck, int *out) {
    const uint8_t *base = (const uint8_t*)pd;
    int off = 0;
    for (int i = 0; i < n; i++) {
        if (zk_verify(base + off, pl[i], cb, ck)) { *out = i; return 1; }
        off += pl[i];
    }
    *out = -1; return 0;
}

/* SHA-1 */
typedef struct { uint32_t h[5]; uint64_t len; uint8_t buf[64]; int idx; } SHA1_CTX;
static inline uint32_t rol32(uint32_t v, int s){return (v<<s)|(v>>(32-s));}
static void sha1_init(SHA1_CTX *c) {
    c->h[0]=0x67452301; c->h[1]=0xEFCDAB89;
    c->h[2]=0x98BADCFE; c->h[3]=0x10325476; c->h[4]=0xC3D2E1F0;
    c->len=0; c->idx=0;
}
static void sha1_block(SHA1_CTX *c, const uint8_t *p) {
    uint32_t w[80];
    for (int i = 0; i < 16; i++)
        w[i] = (uint32_t)p[i*4]<<24 | p[i*4+1]<<16 | p[i*4+2]<<8 | p[i*4+3];
    for (int i = 16; i < 80; i++) w[i] = rol32(w[i-3]^w[i-8]^w[i-14]^w[i-16], 1);
    uint32_t a=c->h[0],b=c->h[1],cc=c->h[2],d=c->h[3],e=c->h[4];
    for (int i = 0; i < 80; i++) {
        uint32_t f,k;
        if (i<20){f=(b&cc)|((~b)&d);k=0x5A827999;}
        else if (i<40){f=b^cc^d;k=0x6ED9EBA1;}
        else if (i<60){f=(b&cc)|(b&d)|(cc&d);k=0x8F1BBCDC;}
        else {f=b^cc^d;k=0xCA62C1D6;}
        uint32_t t = rol32(a,5)+f+e+k+w[i];
        e=d; d=cc; cc=rol32(b,30); b=a; a=t;
    }
    c->h[0]+=a;c->h[1]+=b;c->h[2]+=cc;c->h[3]+=d;c->h[4]+=e;
}
static void sha1_update(SHA1_CTX *c, const uint8_t *p, size_t n) {
    c->len += n;
    while (n) {
        size_t take = 64 - c->idx;
        if (take > n) take = n;
        memcpy(c->buf + c->idx, p, take);
        c->idx += take; p += take; n -= take;
        if (c->idx == 64) { sha1_block(c, c->buf); c->idx = 0; }
    }
}
static void sha1_final(SHA1_CTX *c, uint8_t out[20]) {
    uint64_t bitlen = c->len * 8;
    uint8_t pad = 0x80;
    sha1_update(c, &pad, 1);
    uint8_t zero = 0;
    while (c->idx != 56) sha1_update(c, &zero, 1);
    uint8_t lb[8];
    for (int i = 0; i < 8; i++) lb[i] = (uint8_t)(bitlen >> (56 - i*8));
    sha1_update(c, lb, 8);
    for (int i = 0; i < 5; i++) {
        out[i*4]   = (uint8_t)(c->h[i] >> 24);
        out[i*4+1] = (uint8_t)(c->h[i] >> 16);
        out[i*4+2] = (uint8_t)(c->h[i] >>  8);
        out[i*4+3] = (uint8_t)(c->h[i]);
    }
}

/* AES-256 */
static const uint8_t sbox[256] = {
0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16};
static const uint8_t rcon[11] = {0,1,2,4,8,16,32,64,128,27,54};

typedef struct { uint8_t rk[240]; int nr; } AES256;

static void aes256_expand(AES256 *a, const uint8_t key[32]) {
    uint8_t *w = a->rk;
    memcpy(w, key, 32);
    a->nr = 14;
    int i = 8;
    while (i < 60) {
        uint8_t t[4] = {w[(i-1)*4],w[(i-1)*4+1],w[(i-1)*4+2],w[(i-1)*4+3]};
        if (i % 8 == 0) {
            uint8_t tmp = t[0];
            t[0]=sbox[t[1]]^rcon[i/8]; t[1]=sbox[t[2]]; t[2]=sbox[t[3]]; t[3]=sbox[tmp];
        } else if (i % 8 == 4) {
            t[0]=sbox[t[0]];t[1]=sbox[t[1]];t[2]=sbox[t[2]];t[3]=sbox[t[3]];
        }
        for (int j = 0; j < 4; j++) w[i*4+j] = w[(i-8)*4+j] ^ t[j];
        i++;
    }
}
static uint8_t xtime(uint8_t x){ return (x<<1) ^ ((x>>7)*0x1b); }

static void aes256_encrypt_block(const AES256 *a, uint8_t blk[16]) {
    uint8_t s[16];
    for (int i = 0; i < 16; i++) s[i] = blk[i] ^ a->rk[i];
    for (int r = 1; r <= a->nr; r++) {
        for (int i = 0; i < 16; i++) s[i] = sbox[s[i]];
        uint8_t t;
        t=s[1];s[1]=s[5];s[5]=s[9];s[9]=s[13];s[13]=t;
        t=s[2];s[2]=s[10];s[10]=t; t=s[6];s[6]=s[14];s[14]=t;
        t=s[15];s[15]=s[11];s[11]=s[7];s[7]=s[3];s[3]=t;
        if (r != a->nr) {
            for (int col = 0; col < 4; col++) {
                uint8_t *p = s + col*4;
                uint8_t a0=p[0],a1=p[1],a2=p[2],a3=p[3];
                uint8_t x0=a0^a1^a2^a3;
                p[0]=a0^x0^xtime(a0^a1);
                p[1]=a1^x0^xtime(a1^a2);
                p[2]=a2^x0^xtime(a2^a3);
                p[3]=a3^x0^xtime(a3^a0);
            }
        }
        for (int i = 0; i < 16; i++) s[i] ^= a->rk[r*16+i];
    }
    memcpy(blk, s, 16);
}

static void hmac_sha1(const uint8_t *key, int keylen,
                      const uint8_t *msg, int msglen, uint8_t out[20]) {
    uint8_t k[64]; memset(k, 0, 64);
    if (keylen > 64) {
        SHA1_CTX t; sha1_init(&t); sha1_update(&t, key, keylen);
        sha1_final(&t, k);
    } else memcpy(k, key, keylen);
    uint8_t ipad[64], opad[64];
    for (int i = 0; i < 64; i++) { ipad[i] = k[i]^0x36; opad[i]=k[i]^0x5c; }
    SHA1_CTX ctx; sha1_init(&ctx);
    sha1_update(&ctx, ipad, 64);
    sha1_update(&ctx, msg, msglen);
    uint8_t inner[20]; sha1_final(&ctx, inner);
    sha1_init(&ctx);
    sha1_update(&ctx, opad, 64);
    sha1_update(&ctx, inner, 20);
    sha1_final(&ctx, out);
}

static void pbkdf2_sha1(const uint8_t *pwd, int pwdlen,
                        const uint8_t *salt, int saltlen,
                        int iterations, uint8_t *out, int outlen) {
    uint8_t block[20];
    uint8_t saltblock[256];
    if (saltlen + 4 > 256) return;
    memcpy(saltblock, salt, saltlen);
    int blocks = (outlen + 19) / 20;
    for (int b = 1; b <= blocks; b++) {
        saltblock[saltlen+0]=(b>>24)&0xff;
        saltblock[saltlen+1]=(b>>16)&0xff;
        saltblock[saltlen+2]=(b>>8)&0xff;
        saltblock[saltlen+3]=b&0xff;
        uint8_t U[20]; hmac_sha1(pwd, pwdlen, saltblock, saltlen+4, U);
        memcpy(block, U, 20);
        for (int i = 1; i < iterations; i++) {
            hmac_sha1(pwd, pwdlen, U, 20, U);
            for (int j = 0; j < 20; j++) block[j] ^= U[j];
        }
        int take = outlen - (b-1)*20;
        if (take > 20) take = 20;
        memcpy(out + (b-1)*20, block, take);
    }
}

int winzip_aes_verify(const char *pwd, int pwdlen,
                      const uint8_t *salt, int saltlen, int iterations,
                      const uint8_t *expected_pv) {
    uint8_t derived[66];
    pbkdf2_sha1((const uint8_t*)pwd, pwdlen, salt, saltlen, iterations,
                derived, 66);
    uint8_t pv[2];
    AES256 a; aes256_expand(&a, derived);
    uint8_t blk[16];
    memset(blk, 0, 16);
    memcpy(blk, salt, saltlen < 16 ? saltlen : 16);
    aes256_encrypt_block(&a, blk);
    pv[0] = blk[0]; pv[1] = blk[1];
    return (pv[0]==expected_pv[0] && pv[1]==expected_pv[1]) ? 1 : 0;
}

int winzip_aes_crack_batch(const char *pd, const int *pl, int n,
                           const uint8_t *salt, int saltlen, int iterations,
                           const uint8_t *pv, int *out) {
    const char *base = pd;
    int off = 0;
    for (int i = 0; i < n; i++) {
        if (winzip_aes_verify(base + off, pl[i], salt, saltlen, iterations, pv)) {
            *out = i; return 1;
        }
        off += pl[i];
    }
    *out = -1; return 0;
}
"""

_CACHE_LIB = None


def _build_engines():
    cache_dir = os.path.join(tempfile.gettempdir(), "zipcracker_cache")
    os.makedirs(cache_dir, exist_ok=True)
    hid = hashlib.md5(_C_ENGINES.encode()).hexdigest()[:12]
    lib_path = os.path.join(cache_dir, f"zc_engine_{hid}.so")
    if os.path.exists(lib_path):
        return lib_path
    src = os.path.join(cache_dir, f"zc_engine_{hid}.c")
    with open(src, "w") as f:
        f.write(_C_ENGINES)
    cc = os.environ.get("CC", "cc")
    for extra in (["-O3", "-march=native"], ["-O3"]):
        cmd = [cc, "-shared", "-fPIC"] + extra + ["-o", lib_path, src]
        try:
            subprocess.check_call(cmd, stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL)
            return lib_path
        except (subprocess.CalledProcessError, FileNotFoundError):
            continue
    raise RuntimeError(
        "Could not compile C engine.\n"
        "  Linux  : sudo apt install build-essential\n"
        "  macOS  : xcode-select --install\n"
        "  Windows: install MinGW-w64 and add 'gcc' to PATH"
    )


def get_engine():
    global _CACHE_LIB
    if _CACHE_LIB is not None:
        return _CACHE_LIB
    lib = ctypes.CDLL(_build_engines())
    lib.zipcrypto_crack_batch.restype = ctypes.c_int
    lib.zipcrypto_crack_batch.argtypes = [
        ctypes.c_char_p, ctypes.POINTER(ctypes.c_int), ctypes.c_int,
        ctypes.c_char_p, ctypes.c_ubyte, ctypes.POINTER(ctypes.c_int),
    ]
    lib.winzip_aes_crack_batch.restype = ctypes.c_int
    lib.winzip_aes_crack_batch.argtypes = [
        ctypes.c_char_p, ctypes.POINTER(ctypes.c_int), ctypes.c_int,
        ctypes.c_char_p, ctypes.c_int, ctypes.c_int,
        ctypes.c_char_p, ctypes.POINTER(ctypes.c_int),
    ]
    _CACHE_LIB = lib
    return lib


def crack_batch_zipcrypto(passwords, check_bytes, check_byte):
    lib = get_engine()
    if not passwords:
        return (None, 0)
    encoded, valid = [], []
    for i, p in enumerate(passwords):
        b = p.encode("utf-8", errors="ignore")[:64]
        if b:
            encoded.append(b); valid.append(i)
    if not encoded:
        return (None, 0)
    n = len(encoded)
    buf = b"".join(encoded)
    lens = (ctypes.c_int * n)(*[len(e) for e in encoded])
    out = ctypes.c_int(-1)
    ok = lib.zipcrypto_crack_batch(buf, lens, n, check_bytes,
                                    ctypes.c_ubyte(check_byte),
                                    ctypes.byref(out))
    if ok and 0 <= out.value < len(encoded):
        return (passwords[valid[out.value]], n)
    return (None, n)


def crack_batch_aes_native(passwords, salt, iterations, pv_bytes):
    lib = get_engine()
    if not passwords:
        return (None, 0)
    encoded, valid = [], []
    for i, p in enumerate(passwords):
        b = p.encode("utf-8", errors="ignore")[:64]
        if b:
            encoded.append(b); valid.append(i)
    if not encoded:
        return (None, 0)
    n = len(encoded)
    buf = b"".join(encoded)
    lens = (ctypes.c_int * n)(*[len(e) for e in encoded])
    out = ctypes.c_int(-1)
    ok = lib.winzip_aes_crack_batch(buf, lens, n,
                                     salt, len(salt), iterations,
                                     pv_bytes, ctypes.byref(out))
    if ok and 0 <= out.value < len(encoded):
        return (passwords[valid[out.value]], n)
    return (None, n)


# ═══════════════════════════════════════════════════════════════════════════
#  Hash Extraction
# ═══════════════════════════════════════════════════════════════════════════

import struct
import zipfile

try:
    import pyzipper
    HAS_PYZIPPER = True
except ImportError:
    HAS_PYZIPPER = False


def extract_zip_hash(path):
    with open(path, "rb") as f:
        data = f.read()
    is_aes = b"\x01\x99" in data[:16384]

    if is_aes and not HAS_PYZIPPER:
        raise RuntimeError(
            "This ZIP uses AES-256.\n"
            "Install pyzipper first:\n"
            "    pip install pyzipper"
        )

    opener = pyzipper.AESZipFile if is_aes else zipfile.ZipFile
    with opener(path) as zf:
        infos = [i for i in zf.infolist() if i.compress_size > 0] or zf.infolist()
        target = min(infos, key=lambda i: i.compress_size)
        offset = target.header_offset
        with open(path, "rb") as f:
            f.seek(offset)
            head = f.read(30 + len(target.filename) + len(target.extra) + 128)
        start = 30 + len(target.filename) + len(target.extra)

        if not is_aes:
            enc = head[start:start+12]
            if len(enc) < 12:
                raise ValueError("Could not extract 12-byte header")
            return {
                "type": "zipcrypto",
                "filename": target.filename,
                "check_bytes": enc.hex(),
                "check_byte": (target.CRC >> 24) & 0xFF,
                "source": os.path.basename(path),
            }
        else:
            salt_len = struct.unpack("<H", head[start:start+2])[0]
            salt = head[start+2:start+2+salt_len]
            pv = head[start+2+salt_len:start+2+salt_len+2]
            return {
                "type": "zip_aes",
                "filename": target.filename,
                "salt": salt.hex(),
                "pv": pv.hex(),
                "iterations": 1000,
                "source": os.path.basename(path),
            }


# ═══════════════════════════════════════════════════════════════════════════
#  Rules Engine (John-style)
# ═══════════════════════════════════════════════════════════════════════════

def parse_rule_line(line):
    ops = []
    i = 0
    while i < len(line):
        ch = line[i]
        if ch in " :\t":
            i += 1; continue
        if ch in "lucrdf{}[]":
            ops.append((ch,)); i += 1
        elif ch in "$^":
            if i+1 < len(line): ops.append((ch, line[i+1])); i += 2
            else: i += 1
        elif ch == "T":
            if i+1 < len(line): ops.append((ch, line[i+1])); i += 2
            else: i += 1
        elif ch == "s":
            if i+2 < len(line): ops.append((ch, line[i+1], line[i+2])); i += 3
            else: i += 1
        elif ch in "@z":
            if i+1 < len(line): ops.append((ch, line[i+1])); i += 2
            else: i += 1
        elif ch == "'":
            if i+1 < len(line): ops.append((ch, line[i+1])); i += 2
            else: i += 1
        elif ch == "x":
            if i+2 < len(line): ops.append((ch, line[i+1], line[i+2])); i += 3
            else: i += 1
        else:
            i += 1
    return ops


def apply_rule_ops(word, ops):
    w = word
    for op in ops:
        k = op[0]
        try:
            if k == "l": w = w.lower()
            elif k == "u": w = w.upper()
            elif k == "c": w = w.capitalize()
            elif k == "r": w = w[::-1]
            elif k == "d": w = w + w
            elif k == "f": w = w + w[::-1]
            elif k == "{": w = (w[1:] + w[0]) if w else w
            elif k == "}": w = (w[-1] + w[:-1]) if w else w
            elif k == "$": w = w + op[1]
            elif k == "^": w = op[1] + w
            elif k == "[": w = w[1:]
            elif k == "]": w = w[:-1]
            elif k == "T":
                n = int(op[1])
                if 0 <= n < len(w): w = w[:n] + w[n].swapcase() + w[n+1:]
            elif k == "s": w = w.replace(op[1], op[2])
            elif k == "@": w = w.replace(op[1], "")
            elif k == "z":
                n = int(op[1])
                if w: w = w[0]*n + w
            elif k == "'":
                n = int(op[1]); w = w[:n]
            elif k == "x":
                a, b = int(op[1]), int(op[2]); w = w[a:a+b]
        except Exception:
            pass
    return w


def load_rule_file(path):
    rules = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("["):
                continue
            if line.startswith("List."):
                continue
            if "=" in line and line.split("=")[0].strip().isidentifier():
                continue
            ops = parse_rule_line(line)
            if ops:
                rules.append(ops)
    return rules


# ═══════════════════════════════════════════════════════════════════════════
#  PRINCE
# ═══════════════════════════════════════════════════════════════════════════

def prince_attack(wordlist, max_chain=3, min_len=3, max_len=32):
    words = []
    with open(wordlist, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            w = line.rstrip("\r\n")
            if w and len(w) <= 8:
                words.append(w)
            if len(words) >= 5000:
                break
    if not words:
        return
    queue = deque(words)
    seen = set(words)
    for w in words:
        yield w
    for _ in range(max_chain - 1):
        nq = deque()
        while queue:
            head = queue.popleft()
            for w in words[:200]:
                cand = head + w
                if min_len <= len(cand) <= max_len and cand not in seen:
                    seen.add(cand)
                    yield cand
                    nq.append(cand)
        queue = nq


# ═══════════════════════════════════════════════════════════════════════════
#  Workers
# ═══════════════════════════════════════════════════════════════════════════

_WORKER = {}


def _worker_init(hash_dict):
    _WORKER["h"] = hash_dict


def _worker_check_batch(passwords):
    h = _WORKER["h"]
    if h["type"] == "zipcrypto":
        return crack_batch_zipcrypto(
            passwords,
            bytes.fromhex(h["check_bytes"]),
            h["check_byte"],
        )
    if h["type"] == "zip_aes":
        return crack_batch_aes_native(
            passwords,
            bytes.fromhex(h["salt"]),
            h["iterations"],
            bytes.fromhex(h["pv"]),
        )
    return (None, 0)


# ═══════════════════════════════════════════════════════════════════════════
#  Main Engine
# ═══════════════════════════════════════════════════════════════════════════

CHUNK_SIZE = 20_000


def _chunked(it, size):
    b = []
    for x in it:
        b.append(x)
        if len(b) >= size:
            yield b; b = []
    if b:
        yield b


class CrackEngine:
    def __init__(self, hash_dict, source, source_type,
                 rule_file=None, workers=None, use_gpu=False,
                 checkpoint_dir="checkpoints"):
        self.hash = hash_dict
        self.source = source
        self.source_type = source_type
        self.rule_file = rule_file
        self.rules = load_rule_file(rule_file) if rule_file else None
        self.workers = workers or max(1, os.cpu_count() or 4)
        self.use_gpu = use_gpu
        self.checkpoint_dir = checkpoint_dir
        os.makedirs(checkpoint_dir, exist_ok=True)
        tag = hash_dict.get("source", "target")
        self.checkpoint_file = os.path.join(checkpoint_dir, f"{tag}.ckpt.json")
        self.stop_event = threading.Event()
        self.found_password = None
        self.tested = 0
        self.start_time = 0.0
        self._lock = threading.Lock()

    def _install_signals(self):
        def h(sig, frame):
            self.stop_event.set()
            print(c("\n[!] Stopping... please wait.", C.YELLOW))
        try:
            signal.signal(signal.SIGINT, h)
            if hasattr(signal, "SIGTERM"):
                signal.signal(signal.SIGTERM, h)
        except ValueError:
            pass

    def _save_ckpt(self, position):
        try:
            with open(self.checkpoint_file, "w") as f:
                json.dump({"position": position, "tested": self.tested,
                           "source": str(self.source), "type": self.source_type,
                           "ts": time.time()}, f)
        except Exception: pass

    def _load_ckpt(self):
        if not os.path.isfile(self.checkpoint_file):
            return 0
        try:
            with open(self.checkpoint_file) as f:
                d = json.load(f)
            if d.get("source") != str(self.source): return 0
            if d.get("type") != self.source_type: return 0
            return int(d.get("position", 0))
        except Exception:
            return 0

    @staticmethod
    def _stream_wordlist(path, skip=0):
        with open(path, "r", encoding="utf-8", errors="ignore",
                  buffering=1024 * 1024) as f:
            idx = 0
            for line in f:
                if idx < skip: idx += 1; continue
                idx += 1
                p = line.rstrip("\r\n")
                if p: yield p

    def _password_stream(self, skip):
        if self.source_type == "mask":
            m = self.source
            cs = {"l":"abcdefghijklmnopqrstuvwxyz",
                  "u":"ABCDEFGHIJKLMNOPQRSTUVWXYZ",
                  "d":"0123456789",
                  "s":"!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"}
            cs["a"] = cs["l"]+cs["u"]+cs["d"]+cs["s"]
            groups, i = [], 0
            while i < len(m):
                if m[i] == "?" and i+1 < len(m) and m[i+1] in cs:
                    groups.append(cs[m[i+1]]); i += 2
                else:
                    groups.append(m[i]); i += 1
            total = 1
            for g in groups: total *= len(g)
            for idx in range(skip, total):
                x, chars = idx, []
                for g in reversed(groups):
                    chars.append(g[x % len(g)]); x //= len(g)
                yield "".join(reversed(chars))
        elif self.source_type == "prince":
            yield from prince_attack(self.source)
        else:
            base = self._stream_wordlist(self.source, skip=skip)
            if self.rules:
                for w in base:
                    yield w
                    for ops in self.rules:
                        out = apply_rule_ops(w, ops)
                        if out and out != w:
                            yield out
            else:
                yield from base

    def run(self, resume=True):
        self._install_signals()
        print(c(f"[*] Hash type : {self.hash['type']}", C.MAGENTA))
        print(c(f"[*] Workers   : {self.workers}", C.MAGENTA))
        skip = self._load_ckpt() if resume else 0
        if skip:
            print(c(f"[*] Resuming from: {human_num(skip)}", C.YELLOW))
        self.start_time = time.time()
        position = self._run_cpu(skip)
        self._save_ckpt(0 if self.found_password else position)
        self._print_final(time.time() - self.start_time)
        return self.found_password

    def _run_cpu(self, skip):
        ctx = mp.get_context("spawn")
        stream = self._password_stream(skip)
        position = skip
        last_ckpt = time.time()

        with ProcessPoolExecutor(
            max_workers=self.workers, mp_context=ctx,
            initializer=_worker_init, initargs=(self.hash,),
        ) as ex:
            inflight = set()
            max_inflight = self.workers * 4

            def harvest(futs):
                nonlocal position, last_ckpt
                for f in futs:
                    try: pwd, tested = f.result()
                    except Exception: continue
                    with self._lock:
                        self.tested += tested
                        position += tested
                    if pwd and not self.found_password:
                        self.found_password = pwd
                        self.stop_event.set()
                if time.time() - last_ckpt > 15:
                    self._save_ckpt(position)
                    last_ckpt = time.time()

            try:
                for batch in _chunked(stream, CHUNK_SIZE):
                    if self.stop_event.is_set(): break
                    inflight.add(ex.submit(_worker_check_batch, batch))
                    if len(inflight) >= max_inflight:
                        done, inflight = wait(inflight, timeout=0.1,
                                              return_when=FIRST_COMPLETED)
                        if done: harvest(done)
                        self._print_progress()
                        if self.found_password: break
                if not self.found_password and inflight:
                    done, inflight = wait(inflight, return_when=FIRST_COMPLETED)
                    while done and not self.found_password:
                        harvest(done); self._print_progress()
                        if not inflight: break
                        done, inflight = wait(inflight, return_when=FIRST_COMPLETED)
            except KeyboardInterrupt:
                self.stop_event.set()
        return position

    def _print_progress(self):
        elapsed = time.time() - self.start_time
        speed = self.tested / elapsed if elapsed > 0 else 0
        line = (f"\r{c('[', C.GRAY)}"
                f"{c(human_num(self.tested), C.BLUE)} tested  "
                f"{c(human_speed(speed), C.GREEN)}  "
                f"{c(human_time(elapsed), C.YELLOW)} elapsed")
        print(line, end="", flush=True)

    def _print_final(self, elapsed):
        print()
        line("═", 72)
        if self.found_password:
            print(c("  ✔ PASSWORD FOUND!", C.GREEN + C.BOLD))
            print(c(f"  🔑 {self.found_password}", C.GREEN + C.BOLD))
        else:
            print(c("  ✘ Not found.", C.RED))
        speed = self.tested / elapsed if elapsed > 0 else 0
        print(c(f"  ⏱  {human_time(elapsed)} | "
                f"🔁 {human_num(self.tested)} | "
                f"⚡ {human_speed(speed)}", C.CYAN))
        line("═", 72)


# ═══════════════════════════════════════════════════════════════════════════
#  INTERACTIVE PROMPTS
# ═══════════════════════════════════════════════════════════════════════════

def _clean(p):
    return p.strip().strip('"').strip("'")


def ask_zip_file():
    while True:
        line()
        print(c("  STEP 1 — Target ZIP file", C.CYAN + C.BOLD))
        line()
        print(c("  Tip: you can drag & drop the file into this window.", C.GRAY))
        p = _clean(input(c("[?] ZIP file path: ", C.YELLOW)))
        if not p:
            print(c("[-] Please enter a path.", C.RED))
            continue
        if os.path.isfile(p):
            return p
        print(c(f"[-] File not found: {p}", C.RED))
        print(c(f"[i] Current directory: {os.getcwd()}", C.GRAY))
        print(c("[i] Files here:", C.GRAY))
        try:
            for e in sorted(os.listdir("."))[:15]:
                mark = "/" if os.path.isdir(e) else ""
                print(c(f"      {e}{mark}", C.GRAY))
        except Exception:
            pass


def ask_attack_mode():
    line()
    print(c("  STEP 2 — Attack mode", C.CYAN + C.BOLD))
    line()
    print(c("  [1] Wordlist only", C.CYAN))
    print(c("  [2] Wordlist + Rules  (stronger, slower)", C.CYAN))
    print(c("  [3] Mask pattern      (?u?l?l?l?d?d)", C.CYAN))
    print(c("  [4] PRINCE            (auto-generate from wordlist)", C.CYAN))
    while True:
        ch = input(c("[?] Choose mode [1-4]: ", C.YELLOW)).strip()
        if ch in ("1", "2", "3", "4"):
            return ch
        print(c("[-] Enter 1, 2, 3 or 4", C.RED))


def ask_wordlist():
    # Auto-detect common wordlists
    common = ["rockyou.txt", "wordlist.txt", "passwords.txt",
              "list.txt", "passwords.lst"]
    for name in common:
        if os.path.isfile(name):
            ans = input(c(f"[?] Found '{name}' here. Use it? (Y/n): ",
                          C.YELLOW)).strip().lower()
            if ans in ("", "y", "yes"):
                return name
    while True:
        print(c("  Tip: you can drag & drop the wordlist into this window.", C.GRAY))
        p = _clean(input(c("[?] Wordlist path: ", C.YELLOW)))
        if not p:
            print(c("[-] Please enter a path.", C.RED))
            continue
        if os.path.isfile(p):
            try:
                size = human_size(os.path.getsize(p))
                print(c(f"[+] Wordlist: {p} ({size})", C.GREEN))
            except OSError:
                pass
            return p
        print(c(f"[-] File not found: {p}", C.RED))


def ask_rule_file():
    print()
    print(c("  Rule file options:", C.CYAN))
    print(c("    • Path to a .rule / .conf file (John format)", C.GRAY))
    print(c("    • Or type 'builtin' to use built-in rules", C.GRAY))
    while True:
        p = _clean(input(c("[?] Rule file (or 'builtin'): ", C.YELLOW)))
        if p.lower() == "builtin":
            return "builtin"
        if os.path.isfile(p):
            return p
        print(c(f"[-] File not found: {p}", C.RED))


def ask_mask():
    print()
    print(c("  Charsets: ?l=lower  ?u=upper  ?d=digit  ?s=symbol  ?a=all",
            C.GRAY))
    print(c('  Example : "?u?l?l?l?d?d" → Apple12, Test99, ...', C.GRAY))
    while True:
        m = input(c("[?] Mask: ", C.YELLOW)).strip()
        if m:
            # estimate size
            cs = {"l":26, "u":26, "d":10, "s":32, "a":94}
            size = 1; i = 0
            while i < len(m):
                if m[i] == "?" and i+1 < len(m) and m[i+1] in cs:
                    size *= cs[m[i+1]]; i += 2
                else:
                    i += 1
            print(c(f"[+] Estimated combinations: {human_num(size)}", C.GREEN))
            return m


def ask_workers():
    default = os.cpu_count() or 4
    s = input(c(f"[?] Number of workers [{default}]: ", C.YELLOW)).strip()
    if not s:
        return default
    try:
        n = int(s)
        return n if n > 0 else default
    except ValueError:
        return default


def ask_use_gpu():
    try:
        import pyopencl  # noqa
        ans = input(c("[?] Use GPU? (y/N): ", C.YELLOW)).strip().lower()
        return ans in ("y", "yes")
    except ImportError:
        print(c("[i] GPU not available (pyopencl not installed) — using CPU.",
                C.GRAY))
        return False


# Built-in rule set (used when user types "builtin")
def _builtin_rule_file():
    path = os.path.join(tempfile.gettempdir(), "zipcracker_builtin.rule")
    if not os.path.exists(path):
        with open(path, "w") as f:
            f.write(
                ":\n"            # identity
                "c\n"            # capitalize
                "u\n"            # upper
                "l\n"            # lower
                "r\n"            # reverse
                "d\n"            # duplicate
                "f\n"            # reflect
                "$1\n$2\n$3\n"   # append digit
                "$!\n$@\n$#\n"   # append symbol
                "^1\n"           # prepend digit
            )
    return path


# ═══════════════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════════════

def interactive_main():
    banner()
    line("═", 64)
    print(c("  Welcome! Just answer the questions below.", C.CYAN + C.BOLD))
    line("═", 64)

    # 1. ZIP file
    zip_path = ask_zip_file()

    # 2. Detect format
    print()
    print(c("[*] Detecting encryption...", C.CYAN))
    try:
        hash_dict = extract_zip_hash(zip_path)
    except Exception as e:
        print(c(f"[-] Cannot read ZIP: {e}", C.RED))
        pause_and_exit()
        sys.exit(1)
    fmt_label = "ZipCrypto" if hash_dict["type"] == "zipcrypto" else "AES-256"
    print(c(f"[+] Detected: {fmt_label}", C.GREEN))

    # 3. Attack mode
    mode = ask_attack_mode()

    source = None
    source_type = "wordlist"
    rule_file = None

    if mode == "1":
        print()
        line()
        print(c("  STEP 3 — Wordlist", C.CYAN + C.BOLD))
        line()
        source = ask_wordlist()
        source_type = "wordlist"

    elif mode == "2":
        print()
        line()
        print(c("  STEP 3 — Wordlist + Rules", C.CYAN + C.BOLD))
        line()
        source = ask_wordlist()
        source_type = "wordlist"
        rule_file = ask_rule_file()
        if rule_file == "builtin":
            rule_file = _builtin_rule_file()
            print(c("[+] Using built-in rules", C.GREEN))
        else:
            print(c(f"[+] Using rule file: {rule_file}", C.GREEN))

    elif mode == "3":
        print()
        line()
        print(c("  STEP 3 — Mask pattern", C.CYAN + C.BOLD))
        line()
        source = ask_mask()
        source_type = "mask"

    else:  # mode 4
        print()
        line()
        print(c("  STEP 3 — PRINCE wordlist", C.CYAN + C.BOLD))
        line()
        source = ask_wordlist()
        source_type = "prince"

    # 4. Workers
    print()
    line()
    print(c("  STEP 4 — Performance", C.CYAN + C.BOLD))
    line()
    workers = ask_workers()
    use_gpu = ask_use_gpu()

    # 5. Start
    print()
    line("═", 64)
    print(c("  SUMMARY", C.CYAN + C.BOLD))
    line("═", 64)
    print(c(f"  ZIP        : {zip_path}", C.CYAN))
    print(c(f"  Encryption : {fmt_label}", C.CYAN))
    print(c(f"  Attack     : mode {mode}", C.CYAN))
    if source_type == "mask":
        print(c(f"  Mask       : {source}", C.CYAN))
    else:
        try:
            sz = human_size(os.path.getsize(source))
            print(c(f"  Source     : {source} ({sz})", C.CYAN))
        except OSError:
            print(c(f"  Source     : {source}", C.CYAN))
    if rule_file:
        print(c(f"  Rules      : {rule_file}", C.CYAN))
    print(c(f"  Workers    : {workers}", C.CYAN))
    print(c(f"  GPU        : {'yes' if use_gpu else 'no'}", C.CYAN))
    line("═", 64)

    input(c("\n[?] Press Enter to start cracking (or Ctrl+C to cancel)... ",
            C.YELLOW))

    print()
    engine = CrackEngine(
        hash_dict=hash_dict,
        source=source,
        source_type=source_type,
        rule_file=rule_file,
        workers=workers,
        use_gpu=use_gpu,
    )
    engine.run(resume=True)

    pause_and_exit("Press Enter to exit...")


if __name__ == "__main__":
    mp.freeze_support()
    try:
        interactive_main()
    except KeyboardInterrupt:
        print(c("\n[!] Cancelled by user.", C.YELLOW))
        pause_and_exit()
        sys.exit(130)
    except Exception as e:
        print(c(f"\n[!] Error: {e}", C.RED))
        import traceback
        traceback.print_exc()
        pause_and_exit()
        sys.exit(1)
