.PHONY: install lint test demo run ci

export PYTHONPATH := src

install:
	python -m pip install -e ".[dev]"

lint:
	ruff check .
	ruff format --check .

test:
	pytest

demo:
	python -m ciam_lab.demo

run:
	python -m ciam_lab.serve

ci: lint test demo
