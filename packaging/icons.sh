#!/bin/sh
# Re-render the PNG icons from the SVG. Run after changing the SVG.
#
# The PNGs are committed rather than generated at build time because Flathub
# builds offline and its AppStream step needs an icon it can read without an
# SVG loader, which the freedesktop SDK does not have.
set -eu
cd "$(dirname "$0")/../crates/rpgp-gui/desktop"
for size in 64 128 256; do
    rsvg-convert -w "$size" -h "$size" app.rpgp.rpgp.svg -o "app.rpgp.rpgp-$size.png"
done
echo "rendered 64, 128 and 256 px icons from app.rpgp.rpgp.svg"
