# after-gen/1 test vectors (draft, spec/drafts/after-gen.md)

`vectors.json` gives, for every file here, its `media/1` `{binding, hash, leaves}` or the refusal (`x-*.mp4`, one per
"One reading only" rule; `attack-*.mp4`, the files of the adversarial review: a track relabelled `meta`, an added track,
boxes out of their place, a short `uuid`, an external data reference, 20 tracks of 2^32 samples, a record the XMP
lexical rule does not see, malformed C2PA stores), and, for the files carrying a record, the message id read from C2PA
and XMP, or the reader's refusal, and what `check_after_gen` says against the file's own hash. Its directory and key sets are those of `../answers.json`.
`a.mp4`, `b.mov`, `c.mp4` and their `-remux` copies were made once with ffmpeg 9.0.2 (commands in
`packages/verify-py/tests/test_after_gen.py`); every other file is derived from them by `python tests/test_after_gen.py`.
