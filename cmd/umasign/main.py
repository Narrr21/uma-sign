import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from internal.crypto import keygen
from internal.crypto import sign
from internal.verifier import verify

MODULES = (keygen, sign, verify)


def build_parser():
    p = argparse.ArgumentParser(
        prog = "umasign",
        description = "Tanda tangan dan verifikasi rilis perangkat lunak (RSA-PSS, ECDSA P-256, Ed25519).",
    )
    sub = p.add_subparsers(dest="command", required=True, metavar="command")
    for module in MODULES:
        module.register(sub)

    return p

def main(argv=None):
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())