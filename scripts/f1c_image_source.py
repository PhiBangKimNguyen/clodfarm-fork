"""Compare installed Python bytes in an immutable image with committed Git blobs."""

import argparse
import hashlib
import json
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    args = parser.parse_args()
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    files = subprocess.check_output(["git", "ls-tree", "-r", "--name-only", "HEAD", "clodfarm"])
    expected = {
        name: hashlib.sha256(subprocess.check_output(["git", "show", f"HEAD:{name}"])).hexdigest()
        for name in files.decode("utf-8").splitlines()
        if name.endswith(".py")
    }
    probe = (
        "import hashlib,json; from pathlib import Path; import clodfarm; "
        "root=Path(clodfarm.__file__).parent; "
        "print(json.dumps({'clodfarm/'+p.relative_to(root).as_posix():"
        "hashlib.sha256(p.read_bytes()).hexdigest() for p in root.rglob('*.py')}))"
    )
    installed = json.loads(
        subprocess.check_output(
            [
                "docker",
                "run",
                "--rm",
                "--pull=never",
                "--network=none",
                "--read-only",
                args.image,
                "python",
                "-I",
                "-c",
                probe,
            ],
            text=True,
            timeout=90,
        )
    )
    if installed != expected:
        raise ValueError("installed image source differs from committed Git bytes")
    print(
        json.dumps(
            {
                "format": "clodfarm.image-source/v1",
                "revision": revision,
                "image": args.image,
                "status": "passed",
                "files": expected,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
