#!/usr/bin/env python3
"""
Regression tests for the unit-economics calculator.

Stdlib `unittest` only, matching the repository's zero-dependency rule.

    python3 -m unittest discover -s tests -v

The accounting invariants are the load-bearing ones. A margin tool that
reports a number the operator cannot reproduce by hand is worse than no
tool, because it gets trusted. Those relationships are locked here.
"""

import csv
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "skills" / "unit-economics" / "scripts"))

import unit_economics as ue  # noqa: E402


def product(**overrides) -> ue.Product:
    values = dict(ue.DEFAULTS)
    values.update(overrides)
    return ue.Product(name=values.pop("name", "test"), **values)


class TestRevenue(unittest.TestCase):
    def test_gst_is_removed_from_revenue(self):
        """The listed price includes tax that was never the brand's money."""
        result = ue.compute(product(price=118.0, gst_rate=0.18))
        self.assertAlmostEqual(result.net_revenue, 100.0, places=6)

    def test_discount_reduces_both_gross_and_net(self):
        result = ue.compute(product(price=1000.0, discount=200.0, gst_rate=0.0))
        self.assertAlmostEqual(result.gross, 800.0)
        self.assertAlmostEqual(result.net_revenue, 800.0)

    def test_discount_cannot_push_revenue_negative(self):
        result = ue.compute(product(price=100.0, discount=500.0))
        self.assertEqual(result.gross, 0.0)


class TestCascade(unittest.TestCase):
    def test_margins_are_monotonically_decreasing(self):
        result = ue.compute(
            product(price=1180.0, cogs=300.0, packaging=20.0, ship_forward=60.0, cac=200.0)
        )
        self.assertGreater(result.cm1, result.cm2)
        self.assertGreater(result.cm2, result.cm3)

    def test_cm3_is_cm2_less_acquisition(self):
        result = ue.compute(product(price=1180.0, cogs=300.0, cac=250.0))
        self.assertAlmostEqual(result.cm3, result.cm2 - 250.0, places=6)

    def test_prepaid_only_charges_the_gateway_not_cod(self):
        args = dict(price=1180.0, cogs=300.0, cod_fee=50.0, gateway_rate=0.02)
        result = ue.compute(product(cod_share=0.0, **args))
        # 1000 net - 300 cogs - (1180 * 2%) gateway. No COD handling charge.
        self.assertAlmostEqual(result.cm2, 1000.0 - 300.0 - 23.6, places=6)

    def test_cod_only_charges_the_cod_fee_not_the_gateway(self):
        args = dict(price=1180.0, cogs=300.0, cod_fee=50.0, gateway_rate=0.02)
        result = ue.compute(product(cod_share=1.0, rto_rate=0.0, **args))
        self.assertAlmostEqual(result.cm2, 1000.0 - 300.0 - 50.0, places=6)


class TestReturns(unittest.TestCase):
    def test_rto_reduces_contribution(self):
        args = dict(price=1180.0, cogs=300.0, packaging=20.0, ship_forward=60.0,
                    ship_return=60.0, cod_share=1.0)
        without = ue.compute(product(rto_rate=0.0, **args))
        with_rto = ue.compute(product(rto_rate=0.3, **args))
        self.assertLess(with_rto.cm2, without.cm2)

    def test_rejected_order_recovers_stock_but_not_freight(self):
        """A returned unit goes back on the shelf; the two freight legs and the
        packing do not come back. Product cost must not be charged twice."""
        result = ue.compute(
            product(price=1180.0, cogs=900.0, packaging=20.0, ship_forward=60.0,
                    ship_return=60.0, cod_share=1.0, rto_rate=1.0)
        )
        self.assertAlmostEqual(result.cm2, -(20.0 + 60.0 + 60.0), places=6)

    def test_rto_cost_is_zero_without_cod(self):
        result = ue.compute(product(price=1180.0, cogs=300.0, cod_share=0.0, rto_rate=0.5))
        self.assertEqual(result.rto_cost, 0.0)

    def test_payment_mix_blends_between_the_two_pure_cases(self):
        args = dict(price=1180.0, cogs=300.0, packaging=20.0, ship_forward=60.0,
                    ship_return=60.0, cod_fee=50.0, rto_rate=0.2)
        prepaid = ue.compute(product(cod_share=0.0, **args)).cm2
        cod = ue.compute(product(cod_share=1.0, **args)).cm2
        blended = ue.compute(product(cod_share=0.5, **args)).cm2
        self.assertAlmostEqual(blended, (prepaid + cod) / 2.0, places=6)


class TestDerivedFigures(unittest.TestCase):
    def test_max_cac_is_cm2(self):
        result = ue.compute(product(price=1180.0, cogs=300.0))
        self.assertAlmostEqual(result.max_cac, result.cm2, places=6)

    def test_spending_exactly_max_cac_lands_on_zero(self):
        base = ue.compute(product(price=1180.0, cogs=300.0, ship_forward=60.0))
        result = ue.compute(product(price=1180.0, cogs=300.0, ship_forward=60.0,
                                    cac=base.max_cac))
        self.assertAlmostEqual(result.cm3, 0.0, places=6)

    def test_breakeven_roas_times_contribution_returns_gross(self):
        result = ue.compute(product(price=1180.0, cogs=300.0, ship_forward=60.0))
        self.assertIsNotNone(result.breakeven_roas)
        self.assertAlmostEqual(result.breakeven_roas * result.cm2, result.gross, places=6)

    def test_breakeven_roas_is_unreachable_when_contribution_is_negative(self):
        result = ue.compute(product(price=1180.0, cogs=2000.0))
        self.assertIsNone(result.breakeven_roas)

    def test_discount_floor_lands_on_zero_contribution(self):
        base = product(price=1180.0, cogs=300.0, packaging=20.0, ship_forward=60.0,
                       cod_share=0.4, rto_rate=0.15, ship_return=60.0)
        floor = ue.compute(base).discount_floor
        at_floor = ue.compute(ue._with(base, discount=floor)).cm2
        self.assertAlmostEqual(at_floor, 0.0, places=2)

    def test_a_deeper_discount_than_the_floor_loses_money(self):
        base = product(price=1180.0, cogs=300.0, ship_forward=60.0)
        floor = ue.compute(base).discount_floor
        self.assertLess(ue.compute(ue._with(base, discount=floor + 20.0)).cm2, 0.0)

    def test_discount_floor_is_zero_when_already_underwater(self):
        result = ue.compute(product(price=1180.0, cogs=5000.0))
        self.assertEqual(result.discount_floor, 0.0)


class TestVerdict(unittest.TestCase):
    def test_negative_contribution_is_called_out(self):
        result = ue.compute(product(price=1180.0, cogs=5000.0))
        self.assertIn("loses money", result.verdict)

    def test_acquisition_above_contribution_is_called_out(self):
        result = ue.compute(product(price=1180.0, cogs=300.0, cac=5000.0))
        self.assertIn("acquisition costs more", result.verdict)

    def test_healthy_product_is_called_profitable(self):
        result = ue.compute(product(price=1180.0, cogs=300.0, cac=100.0))
        self.assertIn("profitable", result.verdict)


class TestInputParsing(unittest.TestCase):
    def test_accepts_currency_symbols_and_separators(self):
        self.assertAlmostEqual(ue._number("₹1,499", "price"), 1499.0)
        self.assertAlmostEqual(ue._number("Rs 1,499", "price"), 1499.0)

    def test_percentages_parse_either_way(self):
        self.assertAlmostEqual(ue._number("18%", "gst_rate"), 0.18)
        self.assertAlmostEqual(ue._number("0.18", "gst_rate"), 0.18)

    def test_a_bare_rate_above_one_is_read_as_a_percentage(self):
        """An operator typing 22 in an RTO column means 22%, never 2200%."""
        self.assertAlmostEqual(ue._number("22", "rto_rate"), 0.22)

    def test_a_bare_money_value_above_one_is_left_alone(self):
        self.assertAlmostEqual(ue._number("420", "cogs"), 420.0)

    def test_blank_falls_back_to_the_default(self):
        self.assertEqual(ue._number("", "cogs"), ue.DEFAULTS["cogs"])

    def test_a_non_numeric_value_fails_loudly(self):
        with self.assertRaises(SystemExit):
            ue._number("about four hundred", "cogs")


class TestCsv(unittest.TestCase):
    def _write(self, rows, header):
        handle = tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False, newline="")
        writer = csv.DictWriter(handle, fieldnames=header)
        writer.writeheader()
        writer.writerows(rows)
        handle.close()
        self.addCleanup(lambda: Path(handle.name).unlink(missing_ok=True))
        return Path(handle.name)

    def test_reads_a_minimal_two_column_sheet(self):
        path = self._write([{"name": "Kurta", "price": "1499"}], ["name", "price"])
        products = ue.read_csv(path)
        self.assertEqual(len(products), 1)
        self.assertEqual(products[0].name, "Kurta")
        self.assertAlmostEqual(products[0].price, 1499.0)

    def test_column_names_are_case_and_space_insensitive(self):
        path = self._write([{"SKU": "A", "Ship Forward": "80"}], ["SKU", "Ship Forward"])
        self.assertAlmostEqual(ue.read_csv(path)[0].ship_forward, 80.0)

    def test_missing_columns_take_defaults(self):
        path = self._write([{"name": "A", "price": "1000"}], ["name", "price"])
        self.assertEqual(ue.read_csv(path)[0].cogs, ue.DEFAULTS["cogs"])

    def test_an_empty_sheet_fails_loudly(self):
        path = self._write([], ["name", "price"])
        with self.assertRaises(SystemExit):
            ue.read_csv(path)


class TestRendering(unittest.TestCase):
    def test_report_names_every_margin_stage(self):
        text = ue.render([ue.compute(product(price=1180.0, cogs=300.0))], "₹")
        for label in ("CM1", "CM2", "CM3", "Breakeven ROAS"):
            self.assertIn(label, text)

    def test_multiple_products_are_ranked(self):
        rows = [
            ue.compute(product(name="thin", price=1180.0, cogs=1000.0)),
            ue.compute(product(name="fat", price=1180.0, cogs=100.0)),
        ]
        text = ue.render(rows, "₹")
        self.assertIn("Ranked by CM2", text)
        self.assertLess(text.index("fat", text.index("Ranked")), text.index("thin", text.index("Ranked")))

    def test_rto_line_is_hidden_when_there_are_no_returns(self):
        text = ue.render([ue.compute(product(price=1180.0, cogs=300.0))], "₹")
        self.assertNotIn("RTO losses", text)


class TestCli(unittest.TestCase):
    def test_price_is_required(self):
        import io
        from contextlib import redirect_stderr

        # argparse writes its usage to stderr on error; keep it out of the run.
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            ue.main([])

    def test_json_output_is_machine_readable(self):
        import io, json
        from contextlib import redirect_stdout

        buffer = io.StringIO()
        with redirect_stdout(buffer):
            ue.main(["--price", "1180", "--cogs", "300", "--json"])
        payload = json.loads(buffer.getvalue())
        self.assertEqual(len(payload), 1)
        self.assertIn("cm2", payload[0])


if __name__ == "__main__":
    unittest.main()
