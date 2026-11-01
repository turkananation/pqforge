# pqforge site

Jaspr documentation, same shape as the pqtransport and swissarmyknife sites.
`content/` is the source. `dart pub global run jaspr_cli:jaspr build` writes
`build/jaspr/`, which GitHub Pages deploys.

`index.html`, `styles.css`, `llms.txt`, and the other files without a
Jaspr import are still generated from `tool/visibility/visibility_manifest.json`.
Do not hand-edit those. CI checks them. The Pages workflow builds this Jaspr
app and uploads `build/jaspr` instead of the generated HTML mirror.
