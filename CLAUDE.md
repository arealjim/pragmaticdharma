# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

Pragmatic Dharma is a static landing page currently in placeholder state ("Coming Soon"). Pure HTML/CSS with no dependencies or build system.

## Running Locally

```bash
# Option 1: Python dev server
python3 -m http.server 8000
# Open http://localhost:8000

# Option 2: Direct browser
open index.html
```

## Project Structure

Single file project:
- `index.html` - Landing page with inline CSS

## Design System

- **Layout:** Flexbox centered container (full viewport height)
- **Typography:** System font stack (-apple-system, BlinkMacSystemFont, Segoe UI, Roboto)
- **Colors:** Light gray background (#f5f5f5), dark text (#333, #666)
- **Font:** Light weight (300) with letter-spacing

## Deployment

Static HTML - deploy directly to GitHub Pages, Netlify, Vercel, or any web server.
