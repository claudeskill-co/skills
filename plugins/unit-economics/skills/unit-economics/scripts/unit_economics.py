#!/usr/bin/env python3
"""
Per-order unit economics for a D2C brand.

Answers the four questions that decide whether a SKU is worth selling:
how much is left after every cost, what a customer may cost to acquire,
what ROAS breaks even, and how deep a discount can go before the order
loses money.

Deterministic arithmetic on numbers the operator supplies. No network,
no dependencies beyond the standard library, nothing written outside the
paths given on the command line.

    python3 unit_economics.py --csv products.csv
    python3 unit_economics.py --price 1499 --cogs 420 --cac 380
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from dataclasses import dataclass, asdict
from pathlib import Path

# Fields an operator may set per SKU. Anything omitted falls back to the
# default, so a two-column CSV still produces a usable answer.
DEFAULTS: dict[str, float] = {
    "price": 0.0,           # listed price per unit, GST inclusive
    "discount": 0.0,        # absolute discount off the listed price
    "gst_rate": 0.18,       # GST charged to the customer, as a fraction
    "cogs": 0.0,            # landed product cost, excluding GST
    "packaging": 0.0,       # per-order packing material
    "ship_forward": 0.0,    # per-order forward freight
    "ship_return": 0.0,     # freight back on a rejected COD order
    "gateway_rate": 0.02,   # payment gateway fee on prepaid, as a fraction
    "cod_fee": 0.0,         # per-order COD handling charge
    "cod_share": 0.0,       # fraction of orders paid cash on delivery
    "rto_rate": 0.0,        # fraction of COD orders returned undelivered
    "cac": 0.0,             # marketing cost per order
}

MONEY = {"price", "discount", "cogs", "packaging", "ship_forward", "ship_return", "cod_fee", "cac"}
RATES = {"gst_rate", "gateway_rate", "cod_share", "rto_rate"}


@dataclass
class Product:
    name: str
    price: float
    discount: float
    gst_rate: float
    cogs: float
    packaging: float
    ship_forward: float
    ship_return: float
    gateway_rate: float
    cod_fee: float
    cod_share: float
    rto_rate: float
    cac: float


@dataclass
class Economics:
    """Every intermediate is kept so a number can always be traced to its inputs."""

    name: str
    gross: float
    net_revenue: float
    cm1: float
    cm2: float
    cm3: float
    cm1_pct: float
    cm2_pct: float
    cm3_pct: float
    max_cac: float
    breakeven_roas: float | None
    discount_floor: float
    rto_cost: float
    verdict: str


def _net_revenue(product: Product) -> float:
    """What the brand keeps from the customer's payment, before any cost.

    A listed price in India includes GST, which is collected on behalf of the
    government and is never the brand's money. Treating the listed price as
    revenue is the single most common way a margin gets overstated.
    """
    gross = max(product.price - product.discount, 0.0)
    return gross / (1.0 + product.gst_rate)


@dataclass
class Contributions:
    gross: float
    net: float
    cm1: float
    cm2: float
    cm3: float
    rto_cost: float


def _contributions(product: Product) -> Contributions:
    """The cost cascade. Kept separate from `compute` so the discount search
    can evaluate it repeatedly without recursing back through the summary."""
    gross = max(product.price - product.discount, 0.0)
    net = _net_revenue(product)

    # CM1 - the product itself, before it moves.
    cm1 = net - product.cogs - product.packaging

    # CM2 - after fulfilment and payment collection, blended across the
    # payment mix. Prepaid and COD orders have different cost structures and
    # different odds of ever being delivered, so they are modelled apart and
    # then weighted, rather than averaged into one fictional order.
    prepaid_share = max(0.0, 1.0 - product.cod_share)
    prepaid_cm = cm1 - product.ship_forward - (gross * product.gateway_rate)

    delivered_cm = cm1 - product.ship_forward - product.cod_fee
    # A rejected COD order earns nothing and the stock comes back, so the
    # product cost is recovered but both freight legs and the packing are not.
    rto_cm = -(product.packaging + product.ship_forward + product.ship_return)
    cod_cm = (1.0 - product.rto_rate) * delivered_cm + product.rto_rate * rto_cm

    cm2 = prepaid_share * prepaid_cm + product.cod_share * cod_cm
    cm3 = cm2 - product.cac

    # What the returns actually cost, stated separately because it is the
    # number most often left out of a spreadsheet entirely.
    rto_cost = product.cod_share * product.rto_rate * (delivered_cm - rto_cm)

    return Contributions(gross=gross, net=net, cm1=cm1, cm2=cm2, cm3=cm3, rto_cost=rto_cost)


def compute(product: Product) -> Economics:
    c = _contributions(product)
    gross, net, cm1, cm2, cm3 = c.gross, c.net, c.cm1, c.cm2, c.cm3

    pct = lambda value: (value / net * 100.0) if net > 0 else 0.0

    # Breakeven ROAS: revenue needed per rupee of ad spend for CM3 to reach
    # zero. Quoted on the same revenue base the ad platform reports - gross,
    # what the customer paid - because that is the number being compared.
    breakeven_roas = (gross / cm2) if cm2 > 0 else None

    return Economics(
        name=product.name,
        gross=gross,
        net_revenue=net,
        cm1=cm1,
        cm2=cm2,
        cm3=cm3,
        cm1_pct=pct(cm1),
        cm2_pct=pct(cm2),
        cm3_pct=pct(cm3),
        max_cac=cm2,
        breakeven_roas=breakeven_roas,
        discount_floor=_discount_floor(product),
        rto_cost=c.rto_cost,
        verdict=_verdict(cm2, cm3),
    )


def _discount_floor(product: Product) -> float:
    """The largest discount that still leaves CM2 at or above zero.

    CM2 is linear and decreasing in the discount, so a bisection over
    [0, price] converges without needing the closed form - and stays correct
    if the cost model above ever gains a non-linear term.
    """
    if _contributions(_with(product, discount=0.0)).cm2 <= 0:
        return 0.0

    low, high = 0.0, product.price
    for _ in range(60):
        mid = (low + high) / 2.0
        if _contributions(_with(product, discount=mid)).cm2 >= 0:
            low = mid
        else:
            high = mid
    return low


def _with(product: Product, **changes: float) -> Product:
    return Product(**{**asdict(product), **changes})


def _verdict(cm2: float, cm3: float) -> str:
    if cm2 <= 0:
        return "loses money on every order before any marketing"
    if cm3 <= 0:
        return "contribution positive, but acquisition costs more than it earns"
    return "profitable at the stated acquisition cost"


# --------------------------------------------------------------------------- #
# Input
# --------------------------------------------------------------------------- #

def _number(raw: str, field: str) -> float:
    """Accept 1,499 / ₹1499 / 18% / 0.18 - operators paste all four."""
    text = raw.strip().replace(",", "").replace("₹", "").replace("Rs.", "").replace("Rs", "")
    if not text:
        return DEFAULTS[field]

    percent = text.endswith("%")
    if percent:
        text = text[:-1]

    try:
        value = float(text)
    except ValueError as error:
        raise SystemExit(f"error: {field}={raw!r} is not a number") from error

    if percent:
        value /= 100.0
    elif field in RATES and value > 1.0:
        # "18" in a rate column means 18%, never 1800%.
        value /= 100.0
    return value


def from_row(row: dict[str, str], index: int) -> Product:
    known = {key.strip().lower().replace(" ", "_"): value for key, value in row.items() if key}
    name = (known.pop("name", "") or known.pop("sku", "") or f"row {index}").strip()

    values: dict[str, float] = {}
    for field, default in DEFAULTS.items():
        raw = known.get(field)
        values[field] = _number(raw, field) if raw not in (None, "") else default

    unknown = set(known) - set(DEFAULTS) - {"name", "sku"}
    if unknown:
        print(f"warn: ignoring unrecognised column(s) for {name}: {', '.join(sorted(unknown))}",
              file=sys.stderr)

    return Product(name=name, **values)


def read_csv(path: Path) -> list[Product]:
    with path.open(newline="", encoding="utf-8-sig") as handle:
        rows = list(csv.DictReader(handle))
    if not rows:
        raise SystemExit(f"error: {path} has no data rows")
    return [from_row(row, index) for index, row in enumerate(rows, start=1)]


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #

def render(results: list[Economics], currency: str) -> str:
    lines: list[str] = []
    money = lambda value: f"{currency}{value:,.0f}"

    for result in results:
        lines.append("")
        lines.append(result.name)
        lines.append("-" * max(len(result.name), 44))
        rows = [
            ("Customer pays", money(result.gross)),
            ("Net revenue (ex-GST)", money(result.net_revenue)),
            ("CM1  after product + packing", f"{money(result.cm1)}   {result.cm1_pct:5.1f}%"),
            ("CM2  after shipping + payment", f"{money(result.cm2)}   {result.cm2_pct:5.1f}%"),
            ("CM3  after marketing", f"{money(result.cm3)}   {result.cm3_pct:5.1f}%"),
        ]
        if result.rto_cost > 0:
            rows.append(("  of which RTO losses", f"-{money(result.rto_cost)}"))
        rows += [
            ("Most you can pay per order", money(result.max_cac)),
            ("Breakeven ROAS",
             f"{result.breakeven_roas:.2f}x" if result.breakeven_roas else "unreachable"),
            ("Deepest discount that breaks even", money(result.discount_floor)),
        ]
        width = max(len(label) for label, _ in rows)
        for label, value in rows:
            lines.append(f"  {label.ljust(width)}   {value}")
        lines.append(f"  → {result.verdict}")

    if len(results) > 1:
        lines.append("")
        lines.append("Ranked by CM2 per order")
        lines.append("-" * 44)
        for result in sorted(results, key=lambda item: item.cm2, reverse=True):
            lines.append(f"  {money(result.cm2).rjust(10)}   {result.name}")

    lines.append("")
    lines.append("Estimates from the figures supplied. GST is excluded from revenue;")
    lines.append("verify the rate and the cost inputs against your own books.")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Per-order unit economics for a D2C brand.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--csv", type=Path, help="CSV of SKUs, one row each")
    parser.add_argument("--name", default="product")
    parser.add_argument("--currency", default="₹")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    for field in DEFAULTS:
        parser.add_argument(f"--{field.replace('_', '-')}", type=str, default=None)

    args = parser.parse_args(argv)

    if args.csv:
        products = read_csv(args.csv)
    else:
        values = {
            field: _number(getattr(args, field), field)
            if getattr(args, field) is not None
            else default
            for field, default in DEFAULTS.items()
        }
        if values["price"] <= 0:
            parser.error("give --price, or --csv with a price column")
        products = [Product(name=args.name, **values)]

    results = [compute(product) for product in products]

    if args.json:
        print(json.dumps([asdict(result) for result in results], indent=2))
    else:
        print(render(results, args.currency))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
