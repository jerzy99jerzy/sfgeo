"""Tests for trend/trend.py, including the result published in part three.

The reference values were checked against pymannkendall (original_test) and
statsmodels (multipletests, method="holm"); neither is needed to run these tests.
"""
import contextlib
import importlib.util
import io
import os
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DATA = os.path.join(ROOT, "trend", "data", "s5-2026-10-29_2026-11-15.csv")

spec = importlib.util.spec_from_file_location("trend", os.path.join(ROOT, "trend", "trend.py"))
trend = importlib.util.module_from_spec(spec)
spec.loader.exec_module(trend)


class MannKendall(unittest.TestCase):
    def test_strictly_rising(self):
        s, var, z, p = trend.mann_kendall(list(range(10)))
        self.assertEqual(s, 45)
        self.assertEqual(var, 125)
        self.assertAlmostEqual(z, 44 / 125 ** 0.5)
        self.assertLess(p, 1e-4)

    def test_no_change(self):
        s, var, z, p = trend.mann_kendall([3, 3, 3, 3])
        self.assertEqual((s, z, p), (0, 0.0, 1.0))

    def test_ties_lower_the_variance(self):
        _, var_ties, _, _ = trend.mann_kendall([1, 1, 2, 3, 3, 4])
        _, var_none, _, _ = trend.mann_kendall([1, 2, 3, 4, 5, 6])
        self.assertEqual(var_none, 6 * 5 * 17 / 18)
        self.assertEqual(var_ties, (6 * 5 * 17 - 2 * (2 * 1 * 9)) / 18)

    def test_falling_is_symmetric(self):
        up = trend.mann_kendall([1, 4, 2, 5, 7, 6, 9])
        down = trend.mann_kendall([-v for v in [1, 4, 2, 5, 7, 6, 9]])
        self.assertEqual(up[0], -down[0])
        self.assertAlmostEqual(up[3], down[3])

    def test_too_short(self):
        with self.assertRaises(ValueError):
            trend.mann_kendall([1, 2])


class SenAndHolm(unittest.TestCase):
    def test_sen_slope_of_a_line(self):
        self.assertEqual(trend.sen_slope([2 * i + 5 for i in range(8)]), 2)

    def test_sen_slope_ignores_one_outlier(self):
        self.assertEqual(trend.sen_slope([0, 1, 2, 100, 4, 5, 6]), 1)

    def test_holm_steps_down_and_stops(self):
        out = trend.holm([0.01, 0.04, 0.03, 0.005], 0.05)
        self.assertEqual([r for _, r in out], [True, False, False, True])
        self.assertEqual([round(a, 6) for a, _ in out], [0.03, 0.06, 0.06, 0.02])

    def test_holm_adjusted_values_never_fall(self):
        out = trend.holm([0.2, 0.001, 0.04, 0.5, 0.013], 0.05)
        ranked = sorted(zip([0.2, 0.001, 0.04, 0.5, 0.013], out))
        adjusted = [a for _, (a, _) in ranked]
        self.assertEqual(adjusted, sorted(adjusted))


class PublishedResult(unittest.TestCase):
    """The numbers in the Russia section of part three, from the data in trend/data/."""

    @classmethod
    def setUpClass(cls):
        cls.days = trend.load(DATA)
        cls.p = {}
        cls.slope = {}
        for key, _, _ in trend.SERIES:
            x = [d[key] for d in cls.days]
            cls.p[key] = trend.mann_kendall(x)[3]
            cls.slope[key] = trend.sen_slope(x)
        cls.holm = dict(zip([k for k, _, _ in trend.SERIES],
                            trend.holm([cls.p[k] for k, _, _ in trend.SERIES], 0.05)))

    def test_eighteen_days_and_their_totals(self):
        self.assertEqual(len(self.days), 18)
        self.assertEqual((self.days[0]["day"], self.days[-1]["day"]), ("2026-10-29", "2026-11-15"))
        self.assertEqual(sum(d["arrivals"] for d in self.days), 4151)
        self.assertEqual(sum(d["iran"] for d in self.days), 2231)
        self.assertEqual(sum(d["russia"] for d in self.days), 1005)

    def test_only_russias_share_survives_holm(self):
        survivors = [k for k, (_, rejected) in self.holm.items() if rejected]
        self.assertEqual(survivors, ["russia_share"])
        self.assertAlmostEqual(self.p["russia_share"], 0.0031, places=4)
        self.assertAlmostEqual(self.slope["russia_share"], -0.76, places=2)

    def test_russias_count_does_not(self):
        self.assertAlmostEqual(self.p["russia"], 0.018, places=3)
        self.assertFalse(self.holm["russia"][1])

    def test_the_total_stays_flat(self):
        self.assertGreater(self.p["arrivals"], 0.3)

    def test_ends_of_the_period(self):
        self.assertAlmostEqual(trend.end_share(self.days[:5], "russia"), 29.1, places=1)
        self.assertAlmostEqual(trend.end_share(self.days[-5:], "russia"), 20.2, places=1)

    def test_script_runs(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            trend.main([DATA])
        self.assertIn("Russia's share", out.getvalue())

    def test_inconsistent_export_is_refused(self):
        with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False) as fh:
            fh.write('"_time",iran,russia,arrivals,elsewhere\n"2026-10-29T00:00:00.000+0100",1,1,5,2\n')
        self.addCleanup(os.unlink, fh.name)
        with self.assertRaises(ValueError):
            trend.load(fh.name)


if __name__ == "__main__":
    unittest.main()
