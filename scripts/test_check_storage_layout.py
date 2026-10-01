#!/usr/bin/env python3
"""Synthetic cases for check-storage-layout.py's classification. Needs no forge."""
from __future__ import annotations

import importlib.util
import pathlib
import sys
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parent / "check-storage-layout.py"
spec = importlib.util.spec_from_file_location("check_storage_layout", SCRIPT)
check = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = check
spec.loader.exec_module(check)

WHERE = pathlib.Path("synthetic.storage-layout")
ROOT = "root erc7201:t 0x00"


def classify(old: list[str], new: list[str]) -> str:
    return check.classify(old, new, WHERE)


class Classify(unittest.TestCase):
    def test_a_field_appended_at_the_end_is_an_append(self) -> None:
        old = [ROOT, "field slot=0 offset=0 a: uint256"]
        self.assertEqual(classify(old, old + ["field slot=1 offset=0 b: uint256"]), "append")

    def test_a_reordered_field_is_incompatible(self) -> None:
        old = [ROOT, "field slot=0 offset=0 a: uint256", "field slot=1 offset=0 b: address"]
        new = [ROOT, "field slot=0 offset=0 b: address", "field slot=1 offset=0 a: uint256"]
        self.assertEqual(classify(old, new), "incompatible")

    def test_a_mapping_value_struct_may_grow(self) -> None:
        old = [
            ROOT,
            "field slot=0 offset=0 m: mapping(bytes32 => struct T.S)",
            "struct T.S slot=0 offset=0 x: uint256",
        ]
        self.assertEqual(classify(old, old + ["struct T.S slot=1 offset=0 y: uint256"]), "append")

    def test_an_array_element_struct_may_not_grow(self) -> None:
        old = [
            ROOT,
            "field slot=0 offset=0 history: struct T.Generation[]",
            "struct T.Generation slot=0 offset=0 x: uint256",
        ]
        new = old + ["struct T.Generation slot=1 offset=0 y: uint256"]
        self.assertEqual(classify(old, new), "incompatible")

    def test_an_array_behind_a_mapping_counts_too(self) -> None:
        old = [
            ROOT,
            "field slot=0 offset=0 m: mapping(bytes32 => struct T.G[3])",
            "struct T.G slot=0 offset=0 x: uint256",
        ]
        self.assertEqual(classify(old, old + ["struct T.G slot=1 offset=0 y: uint256"]), "incompatible")

    def test_a_struct_inline_in_an_array_element_may_not_grow(self) -> None:
        old = [
            ROOT,
            "field slot=0 offset=0 history: struct T.Outer[]",
            "struct T.Outer slot=0 offset=0 x: uint256",
            "struct T.Outer slot=1 offset=0 inner: struct T.Inner",
            "struct T.Inner slot=0 offset=0 y: uint256",
        ]
        self.assertEqual(classify(old, old + ["struct T.Inner slot=1 offset=0 z: uint256"]), "incompatible")

    def test_each_contract_appends_on_its_own(self) -> None:
        old = ["contract A slot=0 offset=0 a: uint256", "contract B slot=0 offset=0 b: uint256"]
        new = [
            "contract A slot=0 offset=0 a: uint256",
            "contract A slot=1 offset=0 a2: uint256",
            "contract B slot=0 offset=0 b: uint256",
        ]
        self.assertEqual(classify(old, new), "append")

    def test_a_contract_variable_removed_is_incompatible(self) -> None:
        old = ["contract A slot=0 offset=0 a: uint256", "contract B slot=0 offset=0 b: uint256"]
        self.assertEqual(classify(old, ["contract A slot=0 offset=0 a: uint256"]), "incompatible")

    def test_a_field_renamed_in_place_is_a_rename(self) -> None:
        old = [ROOT, "field slot=0 offset=0 before: uint256", "field slot=1 offset=0 b: address"]
        new = [ROOT, "field slot=0 offset=0 after: uint256", "field slot=1 offset=0 b: address"]
        self.assertEqual(classify(old, new), "rename")

    def test_a_struct_and_its_member_renamed_in_place_are_a_rename(self) -> None:
        old = [
            ROOT,
            "field slot=0 offset=0 m: mapping(bytes32 => struct T.Old)",
            "struct T.Old slot=0 offset=0 owner: address",
        ]
        new = [
            ROOT,
            "field slot=0 offset=0 m: mapping(bytes32 => struct T.New)",
            "struct T.New slot=0 offset=0 wallet: address",
        ]
        self.assertEqual(classify(old, new), "rename")

    def test_a_field_whose_contract_type_is_renamed_is_a_rename(self) -> None:
        old = [ROOT, "field slot=0 offset=0 registry: contract IOld"]
        new = [ROOT, "field slot=0 offset=0 registry: contract INew"]
        self.assertEqual(classify(old, new), "rename")

    def test_a_rename_that_retypes_is_incompatible(self) -> None:
        old = [ROOT, "field slot=0 offset=0 a: uint256"]
        self.assertEqual(classify(old, [ROOT, "field slot=0 offset=0 b: address"]), "incompatible")

    def test_two_fields_of_one_type_swapped_are_incompatible(self) -> None:
        old = [ROOT, "field slot=0 offset=0 a: uint256", "field slot=1 offset=0 b: uint256"]
        new = [ROOT, "field slot=0 offset=0 b: uint256", "field slot=1 offset=0 a: uint256"]
        self.assertEqual(classify(old, new), "incompatible")


class Coverage(unittest.TestCase):
    def test_every_upgradeable_contract_has_a_layout(self) -> None:
        covered = {contract for layout in check.LAYOUTS for contract in layout.contracts}
        found = check.upgradeable_contracts()
        self.assertIn("IdentityRegistry", found)
        self.assertIn("XPlatformVerifier", found)
        self.assertLessEqual(found, covered)


if __name__ == "__main__":
    unittest.main()
