#!/usr/bin/env python3
"""
CipherVault v1.0 — AES-256 File Encryption Tool
Author: Daksh Shah | github.com/daksh-shah9135/ciphervault

Usage:
  python ciphervault.py encrypt secret.txt              # prompts for password
  python ciphervault.py decrypt secret.txt.vault        # prompts for password
  python ciphervault.py hash    myfile.pdf              # multi-algorithm file hash
  python ciphervault.py keygen                          # generate secure random key
  python ciphervault.py encrypt secret.txt --output report.html
"""
import argparse, sys, os, getpass, datetime
from core.crypto   import encrypt_file, decrypt_file, hash_file, generate_key
from core.reporter import generate_report

C = type("C",(),{k:f"\033[{v}m" if sys.stdout.isatty() else ""
    for k,v in {"R":"0","B":"1","GR":"92","RE":"91","CY":"96","YE":"93","BL":"94","GY":"90"}.items()})()

def _pw(confirm=False):
    pw = getpass.getpass(f"  {C.YE}Password: {C.R}")
    if not pw: print(f"{C.RE}Error: password cannot be empty.{C.R}"); sys.exit(1)
    if confirm:
        pw2 = getpass.getpass(f"  {C.YE}Confirm : {C.R}")
        if pw != pw2: print(f"{C.RE}Error: passwords do not match.{C.R}"); sys.exit(1)
    return pw

def banner():
    print(f"""
{C.BL}{C.B}  ██████╗██╗██████╗ ██╗  ██╗███████╗██████╗ ██╗   ██╗ █████╗ ██╗   ██╗██╗  ████████╗
 ██╔════╝██║██╔══██╗██║  ██║██╔════╝██╔══██╗██║   ██║██╔══██╗██║   ██║██║  ╚══██╔══╝
 ██║     ██║██████╔╝███████║█████╗  ██████╔╝██║   ██║███████║██║   ██║██║     ██║
 ██║     ██║██╔═══╝ ██╔══██║██╔══╝  ██╔══██╗╚██╗ ██╔╝██╔══██║██║   ██║██║     ██║
 ╚██████╗██║██║     ██║  ██║███████╗██║  ██║ ╚████╔╝ ██║  ██║╚██████╔╝███████╗██║
  ╚═════╝╚═╝╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝  ╚═══╝  ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝{C.R}
{C.GY}  AES-256 File Encryption Tool  |  v1.0  |  by Daksh Shah{C.R}
""")

def main():
    p = argparse.ArgumentParser(description="CipherVault — AES-256 File Encryption")
    p.add_argument("mode", choices=["encrypt","decrypt","hash","keygen"])
    p.add_argument("file", nargs="?", help="File to process")
    p.add_argument("--output", default=None, help="Custom output filename or HTML report name")
    p.add_argument("--no-report", action="store_true")
    args = p.parse_args()

    banner()
    operations = []

    if args.mode == "keygen":
        key = generate_key(32)
        print(f"  {C.GR}✓ Secure random key (256-bit, base64):{C.R}")
        print(f"\n  {C.CY}{C.B}{key}{C.R}\n")
        print(f"  {C.GY}Store this securely. Never hardcode in source code.{C.R}\n")
        return

    if not args.file:
        print(f"{C.RE}Error: file argument required for '{args.mode}'.{C.R}"); sys.exit(1)
    if not os.path.exists(args.file):
        print(f"{C.RE}Error: '{args.file}' not found.{C.R}"); sys.exit(1)

    if args.mode == "hash":
        print(f"  {C.B}File Integrity Hashes — {args.file}{C.R}\n{'─'*55}")
        result = hash_file(args.file)
        print(f"  File size : {result['size']:,} bytes")
        for algo in ["MD5","SHA1","SHA256","SHA512"]:
            print(f"  {C.CY}{algo:<8}{C.R}: {result[algo]}")
        operations.append({"operation":"hash", **result, "status":"SUCCESS"})

    elif args.mode == "encrypt":
        out = args.output or args.file + ".vault"
        print(f"  {C.B}Encrypting:{C.R} {args.file}  →  {out}")
        print(f"  Algorithm : AES-256-CTR + HMAC-SHA256")
        print(f"  KDF       : PBKDF2-HMAC-SHA256 (200,000 iterations)\n")
        pw = _pw(confirm=True)
        print(f"\n  {C.GY}Encrypting...{C.R}")
        result = encrypt_file(args.file, out, pw)
        print(f"  {C.GR}✓ Encrypted successfully!{C.R}")
        print(f"  Original  : {result['original_size']:,} bytes")
        print(f"  Encrypted : {result['encrypted_size']:,} bytes")
        print(f"  Output    : {out}")
        operations.append({"operation":"encrypt", **result})

    elif args.mode == "decrypt":
        out = args.output or (args.file[:-6] if args.file.endswith(".vault") else args.file + ".decrypted")
        print(f"  {C.B}Decrypting:{C.R} {args.file}  →  {out}\n")
        pw = _pw(confirm=False)
        print(f"\n  {C.GY}Verifying integrity & decrypting...{C.R}")
        try:
            result = decrypt_file(args.file, out, pw)
            print(f"  {C.GR}✓ HMAC integrity verified — file not tampered.{C.R}")
            print(f"  {C.GR}✓ Decrypted successfully!{C.R}")
            print(f"  Output    : {out}  ({result['decrypted_size']:,} bytes)")
            operations.append({"operation":"decrypt", **result})
        except ValueError as e:
            print(f"  {C.RE}✗ FAILED: {e}{C.R}")
            operations.append({"operation":"decrypt","input_file":args.file,"status":"FAILED","error":str(e)})
            sys.exit(1)

    # HTML audit report
    if not args.no_report and operations:
        os.makedirs("reports", exist_ok=True)
        ts  = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        rpt = f"reports/ciphervault_{args.mode}_{ts}.html"
        generate_report(operations, rpt)
        print(f"\n  {C.GR}✓ Audit report:{C.R} {rpt}")

    print(f"\n{C.GY}  CipherVault complete.{C.R}\n")

if __name__ == "__main__":
    main()
