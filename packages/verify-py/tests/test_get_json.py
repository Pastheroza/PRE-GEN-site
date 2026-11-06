"""The default fetcher names itself: Wikidata refuses an anonymous Python client (403), which would leave every
public person unconfirmed."""
import io
import json
import urllib.request

import pregen


def test_the_default_fetcher_sends_a_user_agent(monkeypatch):
    seen = {}

    class Opener:
        def open(self, req, timeout):
            seen.update(req.headers)
            return io.BytesIO(json.dumps({"ok": True}).encode())

    monkeypatch.setattr(urllib.request, "build_opener", lambda *a: Opener())
    assert pregen._get_json("https://www.wikidata.org/wiki/Special:EntityData/Q42.json") == {"ok": True}
    assert seen["User-agent"].startswith(f"pregen-python/{pregen.__version__} ")
