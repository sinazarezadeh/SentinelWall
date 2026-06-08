#!/usr/bin/env bash
# Generates a professional PDF documentation bundle from Markdown sources.
# Requires: pandoc, texlive (or BasicTeX), wkhtmltopdf (fallback)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
OUTPUT_DIR="$ROOT_DIR/docs/output"
VERSION=$(git -C "$ROOT_DIR" describe --tags --abbrev=0 2>/dev/null || echo "v0.1.0")

mkdir -p "$OUTPUT_DIR"

info() { echo "[INFO] $*"; }
success() { echo "[OK] $*"; }
error() { echo "[ERROR] $*" >&2; exit 1; }

# Check dependencies
check_deps() {
    if command -v pandoc &>/dev/null; then
        info "pandoc found: $(pandoc --version | head -1)"
        return 0
    fi
    error "pandoc not found. Install: https://pandoc.org/installing.html"
}

# Build the combined PDF
build_pdf() {
    local output="$OUTPUT_DIR/SentinelWall-${VERSION}-Documentation.pdf"

    info "Generating PDF: $output"

    pandoc \
        --from=markdown+yaml_metadata_block+pipe_tables+fenced_code_blocks \
        --to=pdf \
        --pdf-engine=xelatex \
        --variable=geometry:margin=2.5cm \
        --variable=fontsize=11pt \
        --variable=mainfont="DejaVu Serif" \
        --variable=monofont="DejaVu Sans Mono" \
        --variable=colorlinks=true \
        --variable=linkcolor=blue \
        --variable=urlcolor=blue \
        --variable=toccolor=black \
        --table-of-contents \
        --toc-depth=3 \
        --number-sections \
        --highlight-style=kate \
        --metadata=title:"SentinelWall ${VERSION} — Complete Documentation" \
        --metadata=author:"SentinelWall Project" \
        --metadata=date:"$(date '+%B %Y')" \
        --output="$output" \
        "$ROOT_DIR/README.md" \
        "$ROOT_DIR/ARCHITECTURE.md" \
        "$ROOT_DIR/docs/configuration.md" \
        "$ROOT_DIR/docs/api.md" \
        "$ROOT_DIR/docs/deployment.md" \
        "$ROOT_DIR/SECURITY.md" \
        "$ROOT_DIR/CONTRIBUTING.md"

    success "PDF generated: $output"
}

# Build API reference HTML
build_api_html() {
    local output="$OUTPUT_DIR/SentinelWall-${VERSION}-API-Reference.html"

    info "Generating API reference HTML: $output"

    pandoc \
        --from=markdown \
        --to=html5 \
        --standalone \
        --toc \
        --highlight-style=kate \
        --metadata=title:"SentinelWall API Reference" \
        --output="$output" \
        "$ROOT_DIR/docs/api.md"

    success "API HTML generated: $output"
}

# Build quick-start guide (single page)
build_quickstart() {
    local output="$OUTPUT_DIR/SentinelWall-${VERSION}-QuickStart.pdf"

    info "Generating quick-start guide: $output"

    pandoc \
        --from=markdown \
        --to=pdf \
        --pdf-engine=xelatex \
        --variable=geometry:margin=2cm \
        --variable=fontsize=12pt \
        --highlight-style=kate \
        --metadata=title:"SentinelWall Quick Start Guide" \
        --metadata=date:"$(date '+%B %Y')" \
        --output="$output" \
        "$ROOT_DIR/docs/quickstart.md"

    success "Quick-start guide generated: $output"
}

check_deps

info "Building SentinelWall documentation package (${VERSION})..."
build_pdf
build_api_html

info "Output directory: $OUTPUT_DIR"
ls -lh "$OUTPUT_DIR"
success "Documentation generation complete."
