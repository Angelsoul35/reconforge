.PHONY: install test lint run demo clean
install:
	pip install -e ".[dev]"
test:
	pytest --cov=reconforge --cov-report=term-missing
lint:
	ruff check reconforge tests
run:
	uvicorn reconforge.main:app --reload --port 8000
demo:
	python -m reconforge.cli demo
clean:
	rm -rf .pytest_cache .ruff_cache .coverage htmlcov
