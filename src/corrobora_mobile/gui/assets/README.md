# GUI images

Small copies of the project logo for the window header and the window
icon. They are generated from
`docs/Logo_Icon/Corrobora_Mobile_logo_no_platform_marks.png` (1254 x 1254,
pixel data as in `docs/Logo_Icon/README.md`),
the version of the logo without the Apple logo and the Android robot (see
`docs/Logo_Icon/README.md`), with ImageMagick 6.9.12. The only change to the
artwork here is that the white area outside the rounded square is made
transparent (flood fill from the four corners, 12% fuzz):

```text
for s in 96 64 32 16; do
  convert docs/Logo_Icon/Corrobora_Mobile_logo_no_platform_marks.png -alpha set -fuzz 12% -fill none \
    -draw "color 0,0 floodfill" -draw "color 1253,0 floodfill" \
    -draw "color 0,1253 floodfill" -draw "color 1253,1253 floodfill" \
    -strip -filter Lanczos -resize ${s}x${s} -define png:exclude-chunks=date,time,tIME \
    src/corrobora_mobile/gui/assets/logo-$s.png
done
```

Running it twice produced byte-identical files. The committed copies
also carry a signed C2PA "Content Credentials" record (PNG chunk `caBX`,
signed by Anthropic), added when they were written to the repository; their
pixels are identical to the command's output. If the source logo changes,
regenerate all four.
