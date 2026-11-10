# after-gen/1 test vectors (draft, spec/drafts/after-gen.md)

`vectors.json` gives, for every file here, its `media/1` `{binding, hash, leaves}` or the refusal (`x-*.mp4`, one per
"One reading only" rule; `attack-*.mp4`, the files of the adversarial reviews: a track relabelled `meta`, an added track,
boxes a player reads outside `media/1`'s own (kept as is: another hash), a `cmov`, two of a box `media/1` reads, a short
`uuid`, data references that are not self-contained, 20 tracks of 2^32 samples, records the XMP lexical rule does not
see, malformed C2PA stores; `tiny-kept.mp4`, a `gmhd` media header and a kept box in each part of a track), and, for the files carrying a record, the message id read from C2PA
and XMP, or the reader's refusal, and what `check_after_gen` says against the file's own hash. Its directory and key sets are those of `../answers.json`.
`a.mp4`, `b.mov`, `c.mp4` and their `-remux` copies were made once with ffmpeg 9.0.2 (commands in
`packages/verify-py/tests/test_after_gen.py`); every other file is derived from them by `python tests/test_after_gen.py`.
