# Logo files

| File | Content |
|------|---------|
| `Corrobora_Mobile_logo.png` | Original logo. Contains the Apple logo and the Android robot. |
| `Corrobora_Mobile_logo_no_platform_marks.png` | The same logo with those two marks removed from the phone screen. Used by the GUI. |

## How the version without platform marks was made (2026-11-10)

Source: `Corrobora_Mobile_logo.png`, 1254 x 1254, SHA-256
`68f5811db2334a7ed3bc8370325464cce8d0470b8a5a75c4b3533f681b0955ef`.

Every pixel in the box x 340-524, y 285-699 (the phone screen area holding
the two marks) that lies outside a circle of radius 231 around (720, 455)
(the magnifier ring and its outline) was replaced by harmonic interpolation
from the surrounding screen pixels: each row was first set to a straight
blend between the known pixels at its two ends, then 6,000 Jacobi
iterations of the Laplace equation were applied inside the box. 70,861
pixels were replaced; every pixel outside the box is unchanged
(ImageMagick's difference image trims to exactly that box). The script
(Python with numpy, reading and writing pixels through ImageMagick) gave
byte-identical output on two runs.

Script output: 1254 x 1254, SHA-256
`f87ffbe44f94cdcb5663974defd4d0f188c1aa817fb1d43fea006ab6c9981383`.

The committed file additionally carries a signed C2PA "Content
Credentials" record (PNG chunk `caBX`, signed by Anthropic) stating that
it was produced with Claude. The record was added when the file was
written to the repository; the pixel data is identical to the script
output, and removing that one chunk gives back exactly the bytes above.
Committed file SHA-256:
`08bb905ac275c154a1474bfbeb389ce5856225dfa784bfd91ebe3d8218e44c17`.

Why: Apple's trademark guidelines allow only Apple and its authorized
resellers and licensees to use the Apple logo, and Google's Android brand
guidelines require an attribution line and brand-team review for the
Android robot. Removing both avoids those conditions in the app itself.
