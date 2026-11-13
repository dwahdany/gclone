#!/bin/sh
# Makes the small media fixtures that are committed next to this script. Needs ffmpeg with
# libx264, AAC and libmp3lame (`nix-shell -p ffmpeg --run 'sh make-media.sh'`, or
# `brew install ffmpeg`). The files are test patterns and tones: nothing of anyone's.
#
#   tone.mp3               12 s, 440 Hz, 48 kbit/s MP3
#   clip-moov-at-end.mp4   12 s, 320x180, 10 fps H.264 + AAC, `moov` after the media data
#   clip-faststart.mp4     the same streams, `moov` first
#
# Every frame of the clip shows its own number (testsrc2), so a frame drawn after a seek can
# be told from any other.
set -eu
cd "$(dirname "$0")"
ffmpeg -hide_banner -loglevel error -y -f lavfi -i "sine=frequency=440:duration=12" \
    -c:a libmp3lame -b:a 48k -map_metadata -1 -fflags +bitexact tone.mp3
ffmpeg -hide_banner -loglevel error -y \
    -f lavfi -i "testsrc2=size=320x180:rate=10:duration=12" \
    -f lavfi -i "sine=frequency=330:duration=12" \
    -c:v libx264 -preset veryslow -pix_fmt yuv420p -g 10 -b:v 110k -maxrate 110k -bufsize 220k \
    -c:a aac -b:a 32k -map_metadata -1 -fflags +bitexact -flags:v +bitexact -flags:a +bitexact \
    clip-moov-at-end.mp4
ffmpeg -hide_banner -loglevel error -y -i clip-moov-at-end.mp4 -c copy -map_metadata -1 \
    -fflags +bitexact -movflags +faststart clip-faststart.mp4
ls -l tone.mp3 clip-moov-at-end.mp4 clip-faststart.mp4
