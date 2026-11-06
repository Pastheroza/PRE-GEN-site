"""check_channel_proof: only the person's own channel counts, and a path a host could resolve elsewhere proves nothing."""
import pytest

import pregen

OFFICIAL = ["https://www.instagram.com/cristiano"]
TEXT = lambda url: "PRE-GEN: PG-XXXX-000001V"  # noqa: E731


def test_the_persons_own_channel_counts():
    assert pregen.check_channel_proof("PG-XXXX-000001V", "https://www.instagram.com/cristiano/p/1", OFFICIAL, TEXT)
    assert not pregen.check_channel_proof("PG-XXXX-000001V", "https://www.instagram.com/cristiano_fan/p/1", OFFICIAL, TEXT)


@pytest.mark.parametrize("url", ["https://www.instagram.com/cristiano/../attacker/p/1",
                                 "https://www.instagram.com/cristiano/%2e%2e/attacker",
                                 "https://www.instagram.com/cristiano/%2E./attacker",
                                 "https://www.instagram.com/cristiano%2f..%2fattacker",
                                 "https://www.instagram.com/cristiano/./p/1",
                                 "https://www.instagram.com/cristiano/?s=PRE-GEN:+PG-XXXX-000001V",
                                 "https://www.instagram.com/cristiano/p/1#x"])
def test_a_dot_segment_an_encoded_slash_a_query_or_a_fragment_confirms_nothing(url):
    assert not pregen.check_channel_proof("PG-XXXX-000001V", url, OFFICIAL, TEXT)
