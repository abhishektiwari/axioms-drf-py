.PHONY: help install install-dev clean format lint test build publish docs docs-build docs-server docs-watch

help:
	@echo "Available targets:"
	@echo "  install       - Install package dependencies"
	@echo "  install-dev   - Install package with dev dependencies"
	@echo "  format        - Format code with black and ruff"
	@echo "  lint          - Lint code with ruff"
	@echo "  test          - Run tests with pytest"
	@echo "  build         - Build source and wheel distributions"
	@echo "  clean         - Remove build artifacts and caches"
	@echo "  publish       - Upload package to PyPI"
	@echo "  docs          - Build documentation (alias for docs-build)"
	@echo "  docs-build    - Build documentation with Sphinx"
	@echo "  docs-server   - Serve documentation locally on http://localhost:8010"
	@echo "  docs-watch    - Watch docs and rebuild on changes (requires sphinx-autobuild)"

install:
	pip install -e .

install-dev:
	pip install -e ".[dev]"

clean:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info
	rm -rf src/*.egg-info
	rm -rf .pytest_cache
	rm -rf .ruff_cache
	rm -rf docs/_build
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

format:
	black src/
	ruff check --fix src/

lint:
	ruff check src/

test:
	pytest

build: clean
	python -m build

publish: build
	twine upload dist/*

docs-build:
	cd docs && $(MAKE) html

docs-server:
	@echo "Serving documentation at http://localhost:8010"
	@echo "Press Ctrl+C to stop"
	cd docs/_build/html && python -m http.server 8010

docs-watch:
	@echo "Starting auto-build documentation server at http://localhost:8010"
	@echo "Documentation will rebuild automatically when you save changes"
	@echo "Press Ctrl+C to stop"
	sphinx-autobuild docs docs/_build/html --port 8010 --watch src/
