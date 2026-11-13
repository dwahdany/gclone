#!/bin/sh
# Makes the one large media fixture, which is NOT committed: 20 s of 1280x720 H.264 at
# 20 Mbit/s with AAC, about 50 MB, `moov` first. Only its bit rate matters, not its bytes.
#
#   sh make-big.sh <output file>
#
# Needs ffmpeg with libx264 (`nix-shell -p ffmpeg`, `brew install ffmpeg`).
set -eu
out=${1:?usage: make-big.sh <output file>}
ffmpeg -hide_banner -loglevel error -y \
    -f lavfi -i "testsrc2=size=1280x720:rate=30:duration=20" \
    -f lavfi -i "sine=frequency=220:duration=20" \
    -vf "noise=alls=60:allf=t" \
    -c:v libx264 -preset ultrafast -pix_fmt yuv420p -g 30 \
    -b:v 20M -minrate 20M -maxrate 20M -bufsize 20M -x264-params nal-hrd=cbr \
    -c:a aac -b:a 128k -map_metadata -1 -movflags +faststart "$out"
ls -l "$out"
