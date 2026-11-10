"""Stress test H5: one code, one string. A code in a message is read only in its canonical form; normalising
happens only where a person types it (normalize_code), never on a code taken from a message (TOG-CODE.md §7).
A PG- string is not a code at all (TOG-CODE.md §1)."""
import pytest

import pregen

CANONICAL = {"TOG-000042*": "", "TOG-STD-000123": "", "TOG-SUB-000123": "", "TOG-TEST-000001N": "TEST",
             "TOG-NWRD-000042=": "NWRD", "TOG-LIC-NWRD-ZZZZ-134C-2NDD": "NWRD"}
# Every spelling the stress test routed: invisible and control characters, Unicode spaces either library stripped,
# lower case, case-mapped look-alikes (ﬆ, ſ upper-case onto ASCII), and shapes that are not codes at all.
OTHER_SPELLINGS = ["TOG-TEST-000001N\u200d", "TOG-TEST-000001N\x00", "TOG-TEST-000001N\n", " TOG-TEST-000001N",
                   "\ufeffTOG-TEST-000001N", "TOG-TEST-000001N\u0085", "\x1cTOG-TEST-000001N", "tog-test-000001n",
                   "TOG-TEST-", "TOG-TEST", "TOG-\ufb06D-000123", "TOG-\u017fTD-000123", "TOG-TEST-000001N-",
                   "TOG-NWRD-000042-K"]
# What the frozen PG-CODE called a code: retired, not a code, routed nowhere.
PG_STRINGS = ["PG-000042*", "PG-STD-000123", "PG-SUB-000123", "PG-EDT-000012", "PG-STD-000001-K7M2QX9",
              "PG-TEST-000001N", "PG-NWRD-000042=", "PG-NWRD-RND-000042-ZZZZZZJ"]


@pytest.mark.parametrize("code,issuer", CANONICAL.items())
def test_a_canonical_code_names_its_issuer(code, issuer):
    assert pregen.issuer_of(code) == issuer


@pytest.mark.parametrize("spelling", OTHER_SPELLINGS + PG_STRINGS)
def test_any_other_spelling_is_refused_never_repaired(spelling):
    with pytest.raises(pregen.PregenError):
        pregen.issuer_of(spelling)


def test_only_what_a_person_typed_is_normalised():
    assert pregen.normalize_code("  tog-test-000001n \n") == "TOG-TEST-000001N"
    for typed in ("TOG-\ufb06D-000123", "TOG-TEST-000001N\u200d", "\ufeffTOG-TEST-000001N", "tog-test-", "pg-test-000001n"):
        with pytest.raises(pregen.PregenError):
            pregen.normalize_code(typed)
