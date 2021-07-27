# Breath of the Wild LoopAssetList Converter
Converts blal (Loop Asset List) files from machine code to human-readable format. For LoZ:BotW and other Nintendo games.

## Dependencies
* A dumped copy of Legend of Zelda: Breath of the Wild (for Wii U or Switch)
* Python 3.7+ (64-bit, added to system PATH)

## Setup
1. Download and install Python 3.7+, 64-bit. You must choose the "Add to System PATH" option during installation.
2. Open a command line and run `pip install blal`

### How to Use
First, navigate to the folder that contains the LoopAssetList.blal, then run the following function.

```blal [-b] file```
* `file` - path to the file to convert. Will convert `BLAL` files to `YAML`, and vice versa. Ignores other file types.
* `-b` - Optional. Convert to big endian mode. Ignored when the filetype is not `YAML`

## Contributing
* Issues: https://github.com/GingerAvalanche/blal/issues
* Source: https://github.com/GingerAvalanche/blal

## License
This software is licensed under the terms of the GNU General Public License, version 3+. The source is publicly available on Github.
