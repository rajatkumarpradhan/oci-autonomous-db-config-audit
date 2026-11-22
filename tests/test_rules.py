import unittest

from adb_audit.model import Database
from adb_audit.rules import (
    exit_code,
    rule_prod_fixed_capacity,
    rule_prod_public_everywhere,
    rule_public_without_mtls,
    rule_unlabeled,
    run_all,
)


def db(name="d", access_type="private", mtls=True, auto_scaling=True,
       labels=("prod",), description="desc", tags=("team:x",)):
    return Database(name=name, access_type=access_type, mtls_required=mtls,
                    auto_scaling=auto_scaling, labels=tuple(labels),
                    description=description, tags=tuple(tags))


class TestAdb001(unittest.TestCase):
    def test_fires_prod_everywhere(self):
        out = rule_prod_public_everywhere((db(access_type="everywhere"),))
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].severity, "HIGH")

    def test_quiet_dev_everywhere(self):
        self.assertEqual(rule_prod_public_everywhere((db(access_type="everywhere", labels=("dev",)),)), [])

    def test_quiet_prod_private(self):
        self.assertEqual(rule_prod_public_everywhere((db(),)), [])


class TestAdb002(unittest.TestCase):
    def test_fires_public_tls_allowed(self):
        out = rule_public_without_mtls((db(access_type="allowed-ips", mtls=False),))
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].severity, "MEDIUM")

    def test_quiet_public_mtls_required(self):
        self.assertEqual(rule_public_without_mtls((db(access_type="allowed-ips", mtls=True),)), [])

    def test_quiet_private_no_mtls(self):
        self.assertEqual(rule_public_without_mtls((db(mtls=False),)), [])


class TestAdb003(unittest.TestCase):
    def test_fires_prod_no_autoscaling(self):
        out = rule_prod_fixed_capacity((db(auto_scaling=False),))
        self.assertEqual(len(out), 1)

    def test_quiet_dev_no_autoscaling(self):
        self.assertEqual(rule_prod_fixed_capacity((db(auto_scaling=False, labels=("dev",)),)), [])

    def test_quiet_prod_autoscaling(self):
        self.assertEqual(rule_prod_fixed_capacity((db(),)), [])


class TestAdb004(unittest.TestCase):
    def test_fires_both_missing(self):
        out = rule_unlabeled((db(description=" ", tags=()),))
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].severity, "LOW")

    def test_quiet_description_only(self):
        self.assertEqual(rule_unlabeled((db(tags=()),)), [])


class TestAggregation(unittest.TestCase):
    def test_exit_2_on_high(self):
        self.assertEqual(exit_code(run_all((db(access_type="everywhere"),))), 2)

    def test_exit_1_medium_only(self):
        self.assertEqual(exit_code(run_all((db(auto_scaling=False),))), 1)

    def test_exit_0_clean(self):
        self.assertEqual(exit_code(run_all((db(),))), 0)


if __name__ == "__main__":
    unittest.main()
