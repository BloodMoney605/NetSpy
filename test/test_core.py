#!/usr/bin/env python3

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))

from version import VERSION, VERSION_FULL
from vuln import (
    _parse_version,
    _version_in_range,
    _product_in_summary,
    _is_false_positive,
)
from common import t

passed = 0
failed = 0


def check(name, condition, detail=""):
    global passed, failed
    if condition:
        passed += 1
        print(f"  [OK] {name}")
    else:
        failed += 1
        print(f"  [FAIL] {name} - {detail}")


def test_parse_version():
    check("parse 1.2.3", _parse_version("1.2.3") == (1, 2, 3))
    check("parse 0", _parse_version("0") == (0,))
    check("parse abc", _parse_version("abc") == (0,))
    check("parse 1.2.3.4", _parse_version("1.2.3.4") == (1, 2, 3, 4))


def test_version_in_range():
    check("versions X to Y true", _version_in_range("2.4.6", "versions 2.4.0 to 2.4.10") == True)
    check("versions X to Y inclusive", _version_in_range("2.4.29", "versions 2.2.0 to 2.4.29") == True)
    check("versions X to Y false", _version_in_range("2.5.0", "versions 2.4.0 to 2.4.29") == False)
    check("X through Y true", _version_in_range("2.4.6", "2.4.0 through 2.4.10") == True)
    check("X through Y false", _version_in_range("2.4.6", "8.0.0 through 9.2.0") == False)
    check("before X true", _version_in_range("2.4.6", "before 2.4.10") == True)
    check("before X false", _version_in_range("2.4.6", "before 2.4.5") == False)
    check("prior to X", _version_in_range("2.4.6", "prior to 2.4.10") == True)
    check("through X true", _version_in_range("2.4.6", "through 2.4.10") == True)
    check("through X inclusive", _version_in_range("2.4.6", "through 2.4.6") == True)
    check("X and earlier <= X", _version_in_range("2.4.6", "2.4.6 and earlier") == True)
    check("X and earlier < X", _version_in_range("2.4.5", "2.4.6 and earlier") == True)
    check("X and earlier > X", _version_in_range("2.4.7", "2.4.6 and earlier") == False)


def test_product_in_summary():
    check("multi-word match", _product_in_summary("apache http server", "apache http server 2.4.6") == True)
    check("multi-word no match", _product_in_summary("apache http server", "nginx 1.20") == False)
    check("short name match", _product_in_summary("acl", "the acl package") == True)
    check("short name no substring", _product_in_summary("acl", "aclcheck module") == False)
    check("normal name match", _product_in_summary("python", "python 3.12") == True)


def test_false_positive():
    check("ed in privileged", _is_false_positive("ed", "a privileged vault operator") == True)
    check("dashmachine", _is_false_positive("dash", "rmountjoy92 dashmachine") == True)
    check("dash alliance", _is_false_positive("dash", "DASH 7 Alliance protocol") == True)
    check("winnt mpm", _is_false_positive("apache", "winnt_accept function in winnt mpm") == True)
    check("php cve for apache", _is_false_positive("apache", "in php before 5.4") == True)
    check("apache cve not fp", _is_false_positive("apache", "apache http server before 2.4.30") == False)


print(f"Testing {VERSION_FULL}")
print()

test_parse_version()
test_version_in_range()
test_product_in_summary()
test_false_positive()

print()
print(f"Tests: {passed + failed}  |  Passed: {passed}  |  Failed: {failed}")
sys.exit(0 if failed == 0 else 1)
