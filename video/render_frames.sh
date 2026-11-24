#!/bin/bash
# Render the seekable scene.html to a PNG sequence with headless chromium.
# No ffmpeg needed for this step. Deterministic ?t= renders; parallelized.
DIR=/home/kali/Desktop/ctf-1126/video
OUT="$DIR/frames"
FPS=15
DUR=32            # scene total is 32000 ms
TOTAL=$((FPS*DUR))
PAR=8
mkdir -p "$OUT"
rm -f "$OUT"/*.png

render_one() {
  i="$1"
  DIR=/home/kali/Desktop/ctf-1126/video
  OUT="$DIR/frames"
  FPS=15
  t=$(( i*1000/FPS ))
  n=$(printf "%05d" "$i")
  udd=$(mktemp -d /tmp/cr_XXXXXX)
  chromium --headless=new --no-sandbox --disable-gpu --hide-scrollbars \
    --no-first-run --no-default-browser-check --disable-extensions \
    --disable-software-rasterizer --force-device-scale-factor=1 \
    --window-size=1280,720 --user-data-dir="$udd" \
    --virtual-time-budget=150 --run-all-compositor-stages-before-draw \
    --screenshot="$OUT/f_$n.png" "file://$DIR/scene.html?t=$t" >/dev/null 2>&1
  rm -rf "$udd"
}
export -f render_one

seq 0 $((TOTAL-1)) | xargs -P $PAR -I{} bash -c 'render_one "$@"' _ {}
echo "DONE: rendered $(ls "$OUT"/*.png 2>/dev/null | wc -l) / $TOTAL frames"
