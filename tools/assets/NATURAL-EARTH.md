# Offline operator map

`quantumvpn-world.svg` contains real country geometry compiled from Natural Earth
1:110m admin-0 countries. No client, node, or subscription data is in this asset.
Pins are rendered separately from the operator-maintained coordinate registry.

Source: https://github.com/nvkelso/natural-earth-vector/blob/master/geojson/ne_110m_admin_0_countries.geojson

Public domain: https://www.naturalearthdata.com/about/terms-of-use/

Build with `tools/build-operator-world-map.py`. Projection is equirectangular,
matching the node renderer; all geometry is served offline with the panel.
