import sys

from corrobora_mobile.cli import main

sys.exit(main(["gui", *sys.argv[1:]]))
