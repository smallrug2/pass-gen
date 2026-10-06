========================================
Secure Password Generator (pass_gen.py)
========================================
Coded by: Muse Spark (Meta AI assistant)
Curated by: smallrug2
License: MIT (see LICENSE file)

WHAT IT DOES:
Secure password/passphrase generator using the secrets module (never
random). Two modes: password (random chars, default length 20) and
passphrase (random words from an embedded 1000+ wordlist, ~10 bits per
word). Prints one secret per line with an entropy estimate (bits).

REQUIREMENTS:
Python 3.8+ only - no extra packages needed (stdlib only).

HOW TO RUN:
python pass_gen.py --help
python pass_gen.py
python pass_gen.py --mode password --length 20 --count 5
python pass_gen.py --mode password --no-symbols --no-upper --count 3
python pass_gen.py --mode passphrase --words 5 --sep - --count 3
python pass_gen.py --mode passphrase --words 7 --sep " " --count 2

PLATFORM:
Windows + Linux + Mac: yes.

CREDITS:
- Coded by Muse Spark (Meta AI assistant) for smallrug2's open-source collection.
- If this script helped you, a star on the repo is appreciated.
