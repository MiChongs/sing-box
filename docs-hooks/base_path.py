"""Serve the documentation below a path prefix.

The pages link to each other with root-absolute paths such as
``/zh/configuration/inbound/ebpf/`` because the upstream site lives at a
domain root. MkDocs leaves those links untouched, so below a prefix like
``/sing-box/docs/`` they would leave the site. This hook prefixes every
root-absolute ``href``/``src`` with the path of ``site_url``.
"""

import re
from urllib.parse import urlparse

_ATTRIBUTE = re.compile(r'(\s(?:href|src))="/(?!/)')


def _prefix(config):
    return urlparse(config["site_url"] or "/").path.rstrip("/")


def on_post_page(output, page, config, **kwargs):
    prefix = _prefix(config)
    if not prefix:
        return output

    def rewrite(match):
        return f'{match.group(1)}="{prefix}/'

    # Skip links that already carry the prefix (theme assets, 404 page).
    output = re.sub(
        r'(\s(?:href|src))="' + re.escape(prefix) + '/',
        lambda m: m.group(0).replace('="', '="\x00', 1),
        output,
    )
    output = _ATTRIBUTE.sub(rewrite, output)
    return output.replace('="\x00', '="')
