"""Compile a public-domain Natural Earth GeoJSON into a small offline SVG layer.

This is a build-time converter, never a browser fetch. Map and node pins use the
same equirectangular projection. Input text/properties are not copied into SVG.
"""
import argparse
import hashlib
import json
from pathlib import Path


def render(data):
    paths = []
    for feature in data["features"]:
        geometry = feature["geometry"]
        if not geometry:
            continue
        polygons = geometry["coordinates"]
        if geometry["type"] == "Polygon":
            polygons = [polygons]
        elif geometry["type"] != "MultiPolygon":
            continue
        for polygon in polygons:
            rings = []
            for ring in polygon:
                coords = []
                for lon, lat, *rest in ring:
                    x = 22 + (float(lon) + 180) / 360 * 756
                    y = 18 + (90 - float(lat)) / 180 * 314
                    if not 0 <= x <= 800 or not 0 <= y <= 350:
                        raise ValueError("Invalid geographic coordinate")
                    coords.append(f"{x:.1f},{y:.1f}")
                if len(coords) >= 3:
                    rings.append("M" + "L".join(coords) + "Z")
            if rings:
                paths.append('<path d="' + ''.join(rings) + '"/>')
    if len(paths) < 150:
        raise ValueError("Incomplete world geometry")
    return '<g class="world-countries" fill="url(#world-dots)" fill-rule="evenodd" stroke="#21445b" stroke-width=".5">' + ''.join(paths) + '</g>'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    source = args.source.read_bytes()
    svg = render(json.loads(source))
    args.destination.parent.mkdir(parents=True, exist_ok=True)
    args.destination.write_text(svg + "\n", encoding="utf-8")
    print(json.dumps({"source_sha256": hashlib.sha256(source).hexdigest(), "svg_bytes": len(svg.encode())}))


if __name__ == "__main__":
    main()
