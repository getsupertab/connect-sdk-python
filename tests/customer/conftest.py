import pytest

from connect.customer.token import _LICENSE_TOKEN_CACHE, _LICENSE_TOKEN_LOCKS

SAMPLE_XML = """
<rsl xmlns="https://rslstandard.org/rsl">
  <content url="http://127.0.0.1:7676/*" server="http://127.0.0.1:8787">
    <license type="application/vnd.readium.license.status.v1.0+json">
      <link rel="self" href="http://127.0.0.1:8787/license" />
    </license>
  </content>
  <content url="http://127.0.0.1:7676/article/*" server="http://127.0.0.1:8787">
    <license type="application/vnd.readium.license.status.v1.0+json">
      <link rel="self" href="http://127.0.0.1:8787/license" />
    </license>
  </content>
  <content url="http://127.0.0.1:7676/content" server="http://127.0.0.1:8787">
    <license type="application/vnd.readium.license.status.v1.0+json">
      <link rel="self" href="http://127.0.0.1:8787/license" />
    </license>
  </content>
</rsl>
"""


@pytest.fixture(autouse=True)
def clear_token_cache() -> None:
    _LICENSE_TOKEN_CACHE.clear()
    _LICENSE_TOKEN_LOCKS.clear()
