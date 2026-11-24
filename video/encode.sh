#!/bin/bash
# Encode the rendered PNG sequence into an MP4. Requires ffmpeg.
set -e
DIR=/home/kali/Desktop/ctf-1126/video
OUT="$DIR/frames"
FPS=15
N=$(ls "$OUT"/f_*.png 2>/dev/null | wc -l)
echo "encoding $N frames @ ${FPS}fps ..."
ffmpeg -y -framerate $FPS -i "$OUT/f_%05d.png" \
  -c:v libx264 -preset slow -crf 18 -pix_fmt yuv420p -movflags +faststart \
  "$DIR/challenge-1126-explainer.mp4"
echo "DONE -> $DIR/challenge-1126-explainer.mp4"
ls -lh "$DIR/challenge-1126-explainer.mp4"
