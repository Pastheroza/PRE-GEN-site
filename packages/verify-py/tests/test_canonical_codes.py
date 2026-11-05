"""Stress test H5: one code, one string. A code in a message is read only in its canonical form; normalising
happens only where a person types it (normalize_code), never on a code taken from a message (PG-CODE.md §7)."""
import pytest

import pregen

CANONICAL = {"PG-000042*": "", "PG-STD-000123": "", "PG-SUB-000123": "", "PG-EDT-000012": "",
             "PG-STD-000001-K7M2QX9": "", "PG-TEST-000001N": "TEST", "PG-NWRD-000042=": "NWRD",
             "PG-NWRD-RND-000042-ZZZZZZJ": "NWRD"}
# Every spelling the stress test routed: invisible and control characters, Unicode spaces either library stripped,
# lower case, case-mapped look-alikes (ﬆ, ſ upper-case onto ASCII), and shapes that are not codes at all.
OTHER_SPELLINGS = ["PG-TEST-000001N‍", "PG-TEST-000001N\x00", "PG-TEST-000001N\n", " PG-TEST-000001N",
                   "﻿PG-TEST-000001N", "PG-TEST-000001N\u0085", "\x1cPG-TEST-000001N", "pg-test-000001n",
                   "PG-TEST-", "PG-TEST", "PG-ﬆD-000123", "PG-ſTD-000123", "PG-TEST-000001N-",
                   "PG-NWRD-000042-K"]


@pytest.mark.parametrize("code,issuer", CANONICAL.items())
def test_a_canonical_code_names_its_issuer(code, issuer):
    assert pregen.issuer_of(code) == issuer


@pytest.mark.parametrize("spelling", OTHER_SPELLINGS)
def test_any_other_spelling_is_refused_never_repaired(spelling):
    with pytest.raises(pregen.PregenError):
        pregen.issuer_of(spelling)


def test_only_what_a_person_typed_is_normalised():
    assert pregen.normalize_code("  pg-test-000001n \n") == "PG-TEST-000001N"
    for typed in ("PG-ﬆD-000123", "PG-TEST-000001N‍", "﻿PG-TEST-000001N", "pg-test-"):
        with pytest.raises(pregen.PregenError):
            pregen.normalize_code(typed)
