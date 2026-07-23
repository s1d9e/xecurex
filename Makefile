.PHONY: install test lint format scan clean build

install:
	pip install -e ".[dev]"

test:
	pytest tests/ -v --cov=src/xecurex --cov-report=term-missing

test-html:
	pytest tests/ -v --cov=src/xecurex --cov-report=html
	@echo "Coverage report: htmlcov/index.html"

lint:
	ruff check src/ tests/

format:
	ruff format src/ tests/

scan:
	python -m xecurex .

clean:
	rm -rf build/ dist/ *.egg-info src/*.egg-info .pytest_cache .ruff_cache htmlcov .coverage

build: clean
	python -m build

help:
	@echo "Usage:"
	@echo "  make install    - Install package in dev mode"
	@echo "  make test       - Run tests with coverage"
	@echo "  make test-html  - Generate HTML coverage report"
	@echo "  make lint       - Run linter"
	@echo "  make format     - Format code"
	@echo "  make scan       - Scan current directory"
	@echo "  make clean      - Clean build artifacts"
	@echo "  make build      - Build distribution"
