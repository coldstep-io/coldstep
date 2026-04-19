import unittest

from scripts import elon_orchestrator as E


class PublicSurfaceTests(unittest.TestCase):

    def test_exports_exactly_twelve_public_functions(self):
        public = [name for name in dir(E) if not name.startswith("_")]
        callables = [name for name in public if callable(getattr(E, name))]
        funcs = [n for n in callables if type(getattr(E, n)).__name__ == "function"]
        self.assertEqual(sorted(funcs), sorted([
            "append_index_row",
            "closest_wikilink_match",
            "find_by_tag",
            "find_by_wikilink_target",
            "find_records_for_wiki",
            "load_persona_dial",
            "load_tag_allowlist",
            "read_frontmatter",
            "resolve_wikilink",
            "validate_tag",
            "vault_cli",
            "write_with_frontmatter",
        ]))

    def test_each_public_function_has_a_docstring(self):
        for name in dir(E):
            if name.startswith("_"):
                continue
            obj = getattr(E, name)
            if type(obj).__name__ != "function":
                continue
            self.assertTrue(obj.__doc__, f"{name} is missing a docstring")


if __name__ == "__main__":
    unittest.main()
