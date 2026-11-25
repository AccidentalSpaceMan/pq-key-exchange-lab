"""Draw the benchmark results as one SVG image (no plotting library needed).

Two panels, because sizes (bytes) and speeds (microseconds) are different units and must not
share an axis:

1. bytes sent per key exchange, one bar per scheme;
2. time per operation, grouped by operation, one bar per scheme.

Colours follow a colour-blind-checked palette (blue, orange, aqua), with separate light and
dark steps chosen by the viewer's system theme. Every bar also carries its number as text, so
nothing depends on colour alone. Hovering a bar (when the SVG is opened directly) shows a tooltip.
"""
from __future__ import annotations

from html import escape

from .bench import OPERATIONS, SCHEMES, BenchResult

WIDTH = 760
LEFT = 150          # space for row labels
RIGHT = 90          # space for value labels after the longest bar
PLOT_W = WIDTH - LEFT - RIGHT
FONT = 'system-ui, -apple-system, "Segoe UI", sans-serif'

SERIES_CLASS = {"X25519": "s1", "ML-KEM-768": "s2", "X25519MLKEM768": "s3"}
OP_LABEL = {
    "keygen": "keygen (Bob)",
    "encaps": "encaps (Alice)",
    "decaps": "decaps (Bob)",
}

STYLE = """
  .surface { fill: #fcfcfb; }
  .ink { fill: #0b0b0b; }
  .ink2 { fill: #52514e; }
  .muted { fill: #898781; }
  .grid { stroke: #e1e0d9; stroke-width: 1; }
  .axis { stroke: #c3c2b7; stroke-width: 1; }
  .s1 { fill: #2a78d6; } .s2 { fill: #eb6834; } .s3 { fill: #1baf7a; }
  @media (prefers-color-scheme: dark) {
    .surface { fill: #1a1a19; }
    .ink { fill: #f0efec; }
    .ink2 { fill: #c3c2b7; }
    .grid { stroke: #2c2c2a; }
    .axis { stroke: #383835; }
    .s1 { fill: #3987e5; } .s2 { fill: #d95926; } .s3 { fill: #199e70; }
  }
  text { font-family: %s; }
  .bar:hover { opacity: 0.85; }
""" % FONT


def _nice_scale(value: float, target_ticks: int = 5) -> tuple[float, float]:
    """Pick a round tick step (1, 2 or 5 times a power of ten) and the axis maximum it gives."""
    import math

    if value <= 0:
        return 1.0, 0.2
    raw = value / target_ticks
    exp = 10 ** math.floor(math.log10(raw))
    step = next(m * exp for m in (1, 2, 5, 10) if raw <= m * exp)
    return math.ceil(value / step) * step, step


def _bar(x: float, y: float, w: float, h: float, cls: str, tip: str) -> str:
    """Horizontal bar, square at the baseline, 4px-rounded at the data end."""
    w = max(w, 1.0)
    r = min(4.0, h / 2, w)
    d = (
        f"M{x:.1f},{y:.1f} H{x + w - r:.1f} Q{x + w:.1f},{y:.1f} {x + w:.1f},{y + r:.1f} "
        f"V{y + h - r:.1f} Q{x + w:.1f},{y + h:.1f} {x + w - r:.1f},{y + h:.1f} H{x:.1f} Z"
    )
    return f'<path class="bar {cls}" d="{d}"><title>{escape(tip)}</title></path>'


def _text(x: float, y: float, s: str, cls: str = "ink", size: int = 12, anchor: str = "start", weight: int = 400) -> str:
    return (
        f'<text x="{x:.1f}" y="{y:.1f}" class="{cls}" font-size="{size}" '
        f'text-anchor="{anchor}" font-weight="{weight}">{escape(s)}</text>'
    )


def _axis(y_top: float, y_bottom: float, vmax: float, step: float, unit: str) -> list[str]:
    out = []
    n = round(vmax / step)
    for i in range(n + 1):
        v = step * i
        x = LEFT + PLOT_W * v / vmax
        out.append(f'<line class="{"axis" if i == 0 else "grid"}" x1="{x:.1f}" y1="{y_top:.1f}" x2="{x:.1f}" y2="{y_bottom:.1f}"/>')
        out.append(_text(x, y_bottom + 14, f"{v:,g}" + (f" {unit}" if i == n else ""), "muted", 11, "middle"))
    return out


def render(result: BenchResult) -> str:
    parts: list[str] = []
    y = 28
    parts.append(_text(16, y, "X25519 vs ML-KEM-768 vs the X25519MLKEM768 hybrid", "ink", 16, weight=600))
    y += 20
    env = result.environment
    parts.append(_text(16, y, f"Measured on {env.get('cpu', '?')}, {env.get('os', '?')} · Python {env.get('python', '?')} · "
                              f"cryptography {env.get('cryptography', '?')}", "ink2", 11))

    # Legend (always present for 3 series)
    y += 22
    lx = 16
    for scheme in SCHEMES:
        parts.append(f'<rect class="{SERIES_CLASS[scheme]}" x="{lx}" y="{y - 9}" width="10" height="10" rx="2"/>')
        parts.append(_text(lx + 15, y, scheme, "ink2", 12))
        lx += 30 + len(scheme) * 7.2

    # Panel 1: bytes on the wire
    y += 34
    parts.append(_text(16, y, "Bytes sent per key exchange (public key + reply)", "ink", 13, weight=600))
    y += 14
    bar_h, gap = 18, 8
    wire = {s: result.sizes[s]["on_the_wire"] for s in SCHEMES}
    vmax, step = _nice_scale(max(wire.values()))
    top = y
    bars = []
    for scheme in SCHEMES:
        w = PLOT_W * wire[scheme] / vmax
        s = result.sizes[scheme]
        tip = f"{scheme}: {wire[scheme]:,} bytes = {s['public_key']:,} public key + {s['ciphertext']:,} reply"
        bars.append(_text(LEFT - 10, y + bar_h - 5, scheme, "ink2", 12, "end"))
        bars.append(_bar(LEFT, y, w, bar_h, SERIES_CLASS[scheme], tip))
        bars.append(_text(LEFT + w + 6, y + bar_h - 5, f"{wire[scheme]:,} B", "ink", 12))
        y += bar_h + gap
    parts += _axis(top - 4, y - gap + 4, vmax, step, "B")
    parts += bars

    # Panel 2: time per operation
    y += 46
    parts.append(_text(16, y, "Time per operation, microseconds (median; shorter is faster)", "ink", 13, weight=600))
    y += 14
    bar_h, inner_gap, group_gap = 14, 2, 14
    us = result.microseconds
    vmax, step = _nice_scale(max(us[s][op] for s in SCHEMES for op in OPERATIONS))
    top = y
    bars = []
    for op in OPERATIONS:
        group_h = len(SCHEMES) * bar_h + (len(SCHEMES) - 1) * inner_gap
        bars.append(_text(LEFT - 10, y + group_h / 2 + 4, OP_LABEL[op], "ink2", 12, "end"))
        for scheme in SCHEMES:
            v = us[scheme][op]
            w = PLOT_W * v / vmax
            bars.append(_bar(LEFT, y, w, bar_h, SERIES_CLASS[scheme], f"{scheme} {op}: {v:,.1f} µs"))
            bars.append(_text(LEFT + w + 6, y + bar_h - 3, f"{v:,.1f}", "ink2", 11))
            y += bar_h + inner_gap
        y += group_gap - inner_gap
    parts += _axis(top - 4, y - group_gap + 4, vmax, step, "µs")
    parts += bars

    y += 36
    parts.append(_text(16, y, f"Each time is the median of {result.repeats} runs of {result.iterations:,} calls, "
                              "through Python's cryptography package (includes Python call overhead).", "muted", 11))
    height = int(y + 18)

    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {WIDTH} {height}" width="{WIDTH}" height="{height}" '
        f'role="img" aria-label="Bar charts comparing key exchange sizes and speeds of X25519, ML-KEM-768 and X25519MLKEM768">\n'
        f"<style>{STYLE}</style>\n"
        f'<rect class="surface" width="{WIDTH}" height="{height}" rx="8"/>\n'
        + "\n".join(parts)
        + "\n</svg>\n"
    )
