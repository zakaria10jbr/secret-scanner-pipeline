# tests/test_detectors.py

import unittest

from scanner.detectors import _is_excluded_dir, EXCLUDED_DIR_NAMES


class TestIsExcludedDir(unittest.TestCase):
    def test_git_dir_excluded(self):
        self.assertTrue(_is_excluded_dir(".git"))

    def test_pycache_excluded(self):
        self.assertTrue(_is_excluded_dir("__pycache__"))

    def test_pytest_cache_excluded(self):
        self.assertTrue(_is_excluded_dir(".pytest_cache"))

    def test_node_modules_excluded(self):
        self.assertTrue(_is_excluded_dir("node_modules"))

    def test_egg_info_suffix_excluded_regardless_of_package_name(self):
        # The exact name varies per package (it's derived from the project
        # name), so this must match on suffix, not a fixed string.
        self.assertTrue(_is_excluded_dir("secret_scanner_pipeline.egg-info"))
        self.assertTrue(_is_excluded_dir("some_other_package.egg-info"))

    def test_ordinary_source_dirs_are_not_excluded(self):
        for name in ("scanner", "tests", "config", "scanner-tool", "src", ".aws", ".github"):
            self.assertFalse(_is_excluded_dir(name), f"{name!r} should not be excluded")

    def test_every_fixed_name_in_the_set_is_excluded(self):
        for name in EXCLUDED_DIR_NAMES:
            self.assertTrue(_is_excluded_dir(name))


if __name__ == "__main__":
    unittest.main()
