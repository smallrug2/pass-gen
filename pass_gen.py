"""Secure password and passphrase generator (secrets module).

Uses the `secrets` module (cryptographically strong) -- never `random`.
Two modes: `password` (random chars) and `passphrase` (random words).

Usage examples:
    python pass_gen.py
    python pass_gen.py --mode password --length 20 --count 5
    python pass_gen.py --mode password --no-symbols --no-upper --count 3
    python pass_gen.py --mode passphrase --words 5 --sep - --count 3
    python pass_gen.py --mode passphrase --words 7 --sep " "

Platform notes:
    Windows + Linux + macOS. Pure stdlib (secrets/math); identical
    output format on all three (one secret per line on stdout, entropy
    estimate per secret on stderr so pipes stay clean).

Dependencies:
    Standard library only (argparse, secrets, string, math, sys).
"""

import argparse
import math
import secrets
import string
import sys

SYMBOLS = "!@#$%^&*()-_=+[]{};:,.<>?/|~"

# Embedded wordlist (~1000+ common lowercase words) for passphrases.
# Entropy per word is log2(len(WORDLIST)) ~= 10 bits.
WORDLIST = """
monday tuesday wednesday thursday friday saturday sunday
january february march april may june july august september october november december
morning noon evening night dawn dusk today tomorrow yesterday week month year season spring summer autumn winter
red orange yellow green blue indigo violet pink brown black white gray grey silver gold bronze copper cream beige maroon navy teal olive coral salmon khaki tan
cat dog bird fish horse cow pig sheep goat chicken duck goose turkey deer bear wolf fox lion tiger leopard panther jaguar cheetah zebra giraffe hippo rhino elephant kangaroo koala panda otter beaver mouse rat rabbit squirrel chipmunk hedgehog mole bat owl hawk eagle falcon crow raven sparrow robin finch parrot dove pigeon swan heron crane stork pelican penguin gull shark whale dolphin seal walrus crab lobster shrimp octopus squid clam oyster snail slug worm ant bee wasp hornet fly moth butterfly beetle spider cricket grasshopper frog toad lizard snake turtle tortoise crocodile alligator camel donkey mule llama alpaca bison buffalo elk moose badger weasel skunk raccoon possum armadillo porcupine coyote jackal hyena
apple apricot avocado banana berry cherry coconut grapefruit grape kiwi lemon lime mango melon nectarine olive orange papaya peach pear pineapple plum pomegranate raisin raspberry strawberry tangerine watermelon carrot celery cucumber lettuce spinach kale cabbage broccoli pepper onion garlic potato tomato pumpkin squash bread toast roll bun muffin bagel cake pie cookie brownie donut sugar honey jam jelly syrup butter cheese milk cream yogurt egg bacon sausage ham steak roast stew soup salad pasta noodle rice bean lentil pea corn wheat oat barley rye flour dough pizza burger taco burrito sandwich pancake waffle cereal porridge pudding custard icecream chocolate vanilla caramel cinnamon pepper salt vinegar mustard ketchup mayo coffee tea juice cider soda water
table chair stool bench desk shelf cabinet drawer closet chest trunk box crate basket bin bag case door window wall floor ceiling roof attic basement garage porch patio deck fence gate path road street lane bridge tower castle house hut cabin tent barn shed shop store market mall park garden yard farm field meadow pasture lamp bulb candle lantern torch mirror clock watch radio phone camera speaker bell horn drum flute guitar piano violin trumpet pillow blanket sheet quilt towel rug mat curtain shade soap brush comb towel razor dryer iron kettle pot pan plate cup mug bowl spoon fork knife ladle tray jug bottle jar can tin key lock chain rope cord wire cable nail screw bolt nut hammer saw drill axe shovel rake hoe plow broom mop bucket barrel tank pump fan heater cooler fridge stove oven microwave toaster blender mixer grinder press
river lake pond pool ocean sea wave tide surf beach sand dune cliff bluff mountain hill valley canyon gorge cave cavern forest jungle grove woods tree trunk branch twig leaf root bark flower petal bud blossom grass moss fern vine ivy bush shrub hedge stone rock pebble boulder gravel clay soil mud dust ash smoke fire flame spark ember sun moon star planet comet meteor cloud rain drizzle shower snow sleet hail frost dew fog mist haze wind breeze gust storm thunder lightning rainbow hail spring brook creek stream waterfall rapid delta island peninsula harbor bay cove lagoon reef shore coast desert oasis tundra glacier iceberg volcano lava magma
run walk jog sprint dash rush hurry jump hop skip leap bound climb crawl creep swim float dive sink plunge fly glide soar hover flutter drive ride sail row paddle pedal cruise travel trek hike march stroll wander roam rove explore search seek find lose hide show give take bring carry fetch hold keep drop lift raise lower push pull drag tug tow throw toss catch grab grip seize hold release tie bind knot wrap fold pack load unload pour fill spill leak drip drop splash spray sprinkle wash rinse scrub wipe polish sweep mop dust clean clear tidy burn blaze glow shine gleam sparkle flash flicker blink wink stare gaze glance peek peer look watch view see hear listen speak talk chat whisper shout yell scream laugh giggle chuckle smile grin cry weep sob sigh breathe pant gasp yawn cough sneeze sleep nap doze rest relax wake rise sit stand kneel bow bend stretch twist turn spin twirl roll slide slip skid skate ski sled eat drink bite chew lick sip gulp swallow taste smell touch feel think know learn study read write draw paint sketch carve build make fix mend break smash crash bump hit punch kick slap tickle dance sing hum whistle play game joke tease work rest
happy sad glad merry jolly cheerful bright dark light heavy soft hard rough smooth sharp dull blunt loud quiet silent noisy fast slow quick swift rapid speedy brisk calm still wild tame free brave bold daring fearless kind gentle tender caring cruel harsh rough tough stern strict easy simple plain clear clean dirty messy neat tidy messy sloppy rich wealthy poor broke young old new fresh ancient olden modern fresh stale warm hot cold cool chilly frosty icy snowy rainy sunny cloudy windy stormy humid dry wet damp moist slick smooth sticky gooey sweet sour bitter salty spicy bland rich thin thick wide narrow broad deep shallow tall short high low long brief big small large tiny huge vast giant mini minor major main chief prime
book pen pencil paper letter word story poem novel tale song music tune melody rhythm dance game play toy ball kite doll block puzzle riddle joke riddle path plan idea thought mind heart soul hope faith love hate anger joy sorrow pride shame guilt doubt trust truth lie fact myth dream goal aim hope wish want need like love hate fear brave chief quick quiet early late soon now then here there where when why how what which who whom whose ever never always often seldom rarely once twice daily weekly monthly yearly whole half quarter full empty open shut closed locked free busy idle lazy active swift slow early late first last next prior final total whole part piece chunk slice lump bit drop speck grain pinch dash hint trace path road way route track trail trip tour voyage journey quest tale myth legend hero villain king queen prince princess knight duke lord lady master mistress servant worker farmer baker cook chef driver pilot captain sailor soldier guard scout hunter fisher clerk judge lawyer doctor nurse teacher student pupil class school lesson grade score point mark grade rank level stage phase step grade
""".split()

# Deduplicate while preserving order (keeps entropy claim honest).
_seen = set()
_deduped = []
for _w in WORDLIST:
    _w = _w.strip().lower()
    if _w and _w not in _seen:
        _seen.add(_w)
        _deduped.append(_w)
WORDLIST = _deduped


def password_entropy(pool_size, length):
    """Entropy bits = length * log2(pool)."""
    return length * math.log2(pool_size) if pool_size > 1 else 0.0


def passphrase_entropy(nwords):
    """Entropy bits = words * log2(wordlist size), ~10 bits/word."""
    return nwords * math.log2(len(WORDLIST)) if WORDLIST else 0.0


def make_password(length, use_lower, use_upper, use_digits, use_symbols):
    """Build one password with secrets.choice from the enabled pools."""
    pool = ""
    if use_lower:
        pool += string.ascii_lowercase
    if use_upper:
        pool += string.ascii_uppercase
    if use_digits:
        pool += string.digits
    if use_symbols:
        pool += SYMBOLS
    if not pool:
        raise ValueError("empty character pool (all sets disabled)")
    return "".join(secrets.choice(pool) for _ in range(length)), len(pool)


def make_passphrase(nwords, sep):
    """Build one passphrase with secrets.choice over WORDLIST."""
    return sep.join(secrets.choice(WORDLIST) for _ in range(nwords))


def build_parser():
    p = argparse.ArgumentParser(
        description="Secure password/passphrase generator using the secrets "
                    "module (never random)."
    )
    p.add_argument("--mode", choices=["password", "passphrase"], default="password",
                   help="Output kind (default: %(default)s).")
    p.add_argument("--length", type=int, default=20,
                   help="Password length (default: %(default)s).")
    p.add_argument("--count", type=int, default=1,
                   help="How many secrets to print (default: %(default)s).")
    p.add_argument("--no-symbols", action="store_true", help="Exclude symbols.")
    p.add_argument("--no-digits", action="store_true", help="Exclude digits.")
    p.add_argument("--no-upper", action="store_true", help="Exclude uppercase.")
    p.add_argument("--lower-only", action="store_true",
                   help="Lowercase letters only (overrides other sets).")
    p.add_argument("--words", type=int, default=5,
                   help="Words per passphrase (default: %(default)s).")
    p.add_argument("--sep", default="-",
                   help="Word separator for passphrases (default: %(default)r).")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)

    if args.count < 1 or args.count > 1000:
        print("error: --count must be 1-1000", file=sys.stderr)
        return 2

    # Windows + Linux + macOS: secrets is available on all three with
    # no platform branches needed; line endings handled by print().
    if args.mode == "password":
        if args.length < 1 or args.length > 512:
            print("error: --length must be 1-512", file=sys.stderr)
            return 2
        if args.lower_only:
            use_lower, use_upper, use_digits, use_symbols = True, False, False, False
        else:
            use_lower = True  # always on unless --lower-only path above
            use_upper = not args.no_upper
            use_digits = not args.no_digits
            use_symbols = not args.no_symbols
        try:
            for _ in range(args.count):
                pwd, pool = make_password(
                    args.length, use_lower, use_upper, use_digits, use_symbols)
                print(pwd)  # stdout: secret only, one per line
                bits = password_entropy(pool, args.length)
                print("# entropy: ~%.1f bits (pool=%d, len=%d)"
                      % (bits, pool, args.length), file=sys.stderr)
        except ValueError as e:
            print("error: %s" % e, file=sys.stderr)
            return 2
    else:  # passphrase mode
        if args.words < 1 or args.words > 64:
            print("error: --words must be 1-64", file=sys.stderr)
            return 2
        if len(WORDLIST) < 1000:
            print("error: internal wordlist too small (%d)" % len(WORDLIST),
                  file=sys.stderr)
            return 1
        per_word = math.log2(len(WORDLIST))
        for _ in range(args.count):
            phrase = make_passphrase(args.words, args.sep)
            print(phrase)  # stdout: secret only, one per line
            bits = passphrase_entropy(args.words)
            print("# entropy: ~%.1f bits (%d words x ~%.1f bits, wordlist=%d)"
                  % (bits, args.words, per_word, len(WORDLIST)), file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
