# after-gen/1 test vectors (draft, spec/drafts/after-gen.md)

`vectors.json` gives, for every file here, its `media/1` `{binding, hash, leaves}` or the refusal (`x-*.mp4`, one per
"One reading only" rule; `attack-*.mp4`, the files of the adversarial reviews: a track relabelled `meta`, an added track,
boxes a player reads anywhere, track order, the file type, durations and language (each another hash), a `cmov`, a short
`uuid`, data references that are not self-contained, chunk offsets outside `mdat` or chunks running past it, 20 tracks of
2^32 samples, tables outside their place or that read two ways, sound read by chunk whose entry does not give its sample
size, a second movie (`cmov`, `hoov`, the MPEG handler pattern), a carrier first or not what it claims, records the XMP lexical rule does not see, malformed C2PA stores, and boxes that are not known or not whole: a short `mdhd`, a `dref` count past its entries, a `hdlr` in `stbl`, an unknown box in `trak`; `tiny-title-stco.mp4` holds a title that spells `stco`, read as text), and, for the files carrying a record, the message id read from C2PA
and XMP, or the reader's refusal, and what `check_after_gen` says against the file's own hash. The XMP files also carry the readable codes
(`pgag:Code`, `pgag:Licence`); `vectors.json` gives the copies read and checks the XMP record with them: a copy that
differs is refused (`a-xmp-code-*`, `a-xmp-licence-is-code`, `a-xmp-terms-licence`), and a copy written twice or as an
attribute leaves the packet with no record (`attack-xmp-code-*`). Its directory and key sets are those of `../answers.json`.
`a.mp4`, `b.mov`, `c.mp4` and their `-remux` copies were made once with ffmpeg 9.0.2 (commands in
`packages/verify-py/tests/test_after_gen.py`); every other file is derived from them by `python tests/test_after_gen.py`.
