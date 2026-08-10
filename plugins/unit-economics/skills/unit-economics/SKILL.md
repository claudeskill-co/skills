---
name: unit-economics
description: Work out what a D2C order actually earns after GST, product cost, packing, shipping, payment fees, COD returns and marketing - CM1/CM2/CM3, the most you can pay to acquire a customer, breakeven ROAS, and how deep a discount can go before the order loses money. Use when the user asks about margin, unit economics, contribution margin, CM1/CM2/CM3, breakeven ROAS, max CAC, whether a product or a discount is profitable, what RTO is costing them, or how to price a SKU.
---

# Unit economics

Most margin spreadsheets overstate profit in the same three ways: they count
GST as revenue, they leave returns out entirely, and they stop at gross margin
instead of following the order all the way to the bank. This walks the whole
cascade.

## Ask for what you need, then run the script

The arithmetic is deterministic, so run `scripts/unit_economics.py` rather than
doing it in your head — it is faster, and the operator can re-run it.

Minimum useful input is **selling price** and **product cost**. Everything else
defaults to zero (or to 18% GST and a 2% gateway fee), and every default is
visible in the output, so a partial answer is still honest rather than wrong.

Ask for whatever is missing, in this order of impact:

1. Selling price and landed product cost
2. Payment mix — what share is cash on delivery
3. RTO rate on those COD orders (this is usually the biggest hidden cost)
4. Forward and return shipping, packing
5. Marketing cost per order

Do not invent a number the operator did not give. If they do not know their RTO
rate, say what the answer looks like at 15% and at 25% rather than picking one.

## Running it

```bash
# One SKU
python3 scripts/unit_economics.py \
  --price 1499 --cogs 420 --packaging 35 \
  --ship-forward 75 --ship-return 70 \
  --cod-share 60% --rto-rate 22% --cod-fee 25 \
  --cac 380

# A whole catalogue
python3 scripts/unit_economics.py --csv products.csv

# For further analysis
python3 scripts/unit_economics.py --csv products.csv --json
```

If the operator uploads a spreadsheet, save it as CSV and pass `--csv`. Column
names are matched case-insensitively with spaces treated as underscores, so
`Ship Forward` and `ship_forward` both work. Recognised columns:

`name` / `sku`, `price`, `discount`, `gst_rate`, `cogs`, `packaging`,
`ship_forward`, `ship_return`, `gateway_rate`, `cod_fee`, `cod_share`,
`rto_rate`, `cac`

Values may be written as `1,499`, `₹1499`, `18%` or `0.18`. Anything not
recognised is reported, not silently dropped.

## Reading the output

| Line | What it means |
|---|---|
| **Net revenue** | The price less GST. GST was never the brand's money. |
| **CM1** | After product and packing. Whether the thing is worth making. |
| **CM2** | After shipping and payment collection, blended across the payment mix. **This is the number that matters.** |
| **CM3** | After marketing. Whether the business, not just the product, works. |
| **Most you can pay per order** | Equals CM2. Spend more than this to acquire an order and it loses money. |
| **Breakeven ROAS** | Revenue needed per rupee of ad spend to land at zero. Quoted on gross revenue, the same base ad platforms report. |
| **Deepest discount that breaks even** | Past this, the order is sold at a loss. |

## What to say about the result

- **CM2 negative** — the order loses money before a single rupee of marketing.
  No amount of scale fixes this. Price, product cost or shipping has to change.
- **CM2 positive, CM3 negative** — the product works, the acquisition does not.
  Either CAC comes down or the price goes up; growing spend makes it worse.
- **Both positive** — say how much headroom there is between current CAC and
  max CAC, because that gap is the entire growth budget.

Always name the biggest single line item between net revenue and CM2. It is
usually RTO or shipping, and it is usually the one nobody is tracking.

## Honest limits

- These are **estimates from the figures supplied**, not accounts. Say so.
- GST input credit on costs is not modelled; costs are treated as already
  net of recoverable tax. If the operator is not registered, or cannot claim
  credit, their real margin is lower than this shows.
- Returns are modelled as stock recovered and freight lost. Goods that come
  back damaged or unsellable are worse than this — adjust `cogs` upward or
  treat a share of returns as a write-off.
- One order at a time. Repeat purchase, lifetime value and fixed overhead are
  outside this; a product can be CM3-positive and the business still lose money.
