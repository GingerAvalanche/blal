from pathlib import Path
from yaml import load, dump, CSafeLoader as loader, CSafeDumper as dumper

import argparse

from . import BLAL


def convert_yaml(file: Path) -> None:
    text = dump(BLAL(file.read_bytes()).to_yaml(), default_flow_style=False, Dumper=dumper)
    if file.with_suffix(".yml").exists():
        file.with_suffix(".yml").rename(file.with_suffix(".yml.bak"))
    file.with_suffix(".yml").write_text(text)


def convert_blal(file: Path, bigendian: bool) -> None:
    data = BLAL(load(file.read_text(), Loader=loader), bigendian).to_bytes()
    if file.with_suffix(".blal").exists():
        file.with_suffix(".blal").rename(file.with_suffix(".blal.bak"))
    file.with_suffix(".blal").write_bytes(data)


def main() -> None:
    parser = argparse.ArgumentParser(description="Tool for converting LoopAssetList in LoZ:BotW")
    parser.add_argument(
        "file",
        help="Filename to be converted (accepts wildcards for converting multiple files)",
    )
    parser.add_argument(
        "-b",
        "--bigendian",
        help="Use big endian mode",
        action="store_true",
    )

    args = parser.parse_args()

    file = Path(args.file)
    if not file.suffix == ".blal" and not file.suffix == ".yml" and not file.suffix == ".yaml":
        raise ValueError(f"{file.suffix} is not one of: .blal, .yml, .yaml")

    to_yaml: bool = False
    if file.suffix == ".blal":
        to_yaml = True
        if args.bigendian:
            print(
                f"WARNING: -b is ignored when converting .blal files. Make sure to use it when converting back"
            )

    if to_yaml:
        convert_yaml(file)
    else:
        convert_blal(file, args.bigendian)


if __name__ == "__main__":
    main()
