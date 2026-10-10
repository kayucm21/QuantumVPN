"""Offline presentation checks for the bounded Quantum 4.0 plan."""
from html.parser import HTMLParser
import unittest
from urllib.parse import parse_qs, urlsplit

from tools.quantumvpn_four_catalog import catalog
from tools.quantumvpn_four_ui import render_roadmap


class Elements(HTMLParser):
    def __init__(self, source):
        super().__init__()
        self.nodes = []
        self.text = []
        self.stack = []
        self.feed(source)

    def handle_starttag(self, tag, attrs):
        self.nodes.append((tag, dict(attrs)))
        if tag not in {"input", "meta", "link", "br", "hr", "img"}:
            self.stack.append(tag)

    def handle_endtag(self, tag):
        for offset in range(len(self.stack) - 1, -1, -1):
            if self.stack[offset] == tag:
                del self.stack[offset:]
                break

    def handle_data(self, value):
        if not {"style", "script"}.intersection(self.stack):
            self.text.append(value)


class FourUITests(unittest.TestCase):
    def test_default_is_bounded_and_honest(self):
        source = render_roadmap(catalog())
        parsed = Elements(source)
        self.assertEqual(sum(tag == "tr" for tag, _ in parsed.nodes), 21)
        self.assertIn("Всего: 100", source)
        self.assertIn("Это план развития", source)
        self.assertIn("1–20 из 100", source)
        self.assertNotIn("100%", "".join(parsed.text))
        self.assertTrue(all(attrs.get("method") == "get" for tag, attrs in parsed.nodes if tag == "form"))
        self.assertFalse(any(tag == "script" for tag, _ in parsed.nodes))

    def test_filters_and_pagination_are_preserved(self):
        source = render_roadmap(catalog(group="panel", limit=5, offset=5), "", "panel")
        parsed = Elements(source)
        pages = [parse_qs(urlsplit(attrs["href"]).query) for tag, attrs in parsed.nodes if tag == "a"]
        self.assertEqual(len(pages), 1)
        self.assertEqual(pages[0]["tab"], ["roadmap"])
        self.assertEqual(pages[0]["roadmap_group"], ["panel"])
        self.assertEqual(pages[0]["roadmap_limit"], ["5"])
        self.assertEqual(pages[0]["roadmap_offset"], ["0"])
        self.assertIn("6–10 из 10", source)

    def test_text_and_query_are_escaped(self):
        snapshot = catalog(limit=1)
        snapshot["items"][0].update(title='<img src=x onerror="bad">', description="<script>bad</script>", note="</td><svg>")
        source = render_roadmap(snapshot, '\"><script>bad</script>')
        parsed = Elements(source)
        self.assertFalse(any(tag in {"script", "img", "svg"} for tag, _ in parsed.nodes))
        self.assertIn("&lt;img", source)
        pages = [parse_qs(urlsplit(attrs["href"]).query) for tag, attrs in parsed.nodes if tag == "a"]
        self.assertEqual(pages[0]["q"], ['\"><script>bad</script>'])

    def test_empty_search_has_no_page_link(self):
        source = render_roadmap(catalog("unmatched-test-query"), "unmatched-test-query")
        self.assertIn("Показано 0–0 из 0", source)
        self.assertNotIn("class=\"button secondary\"", source)


if __name__ == "__main__":
    unittest.main()
