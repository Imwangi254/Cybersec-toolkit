.PHONY: install test lint fmt examples all

install:
	pip install -e '.[dev,langchain]'

test:
	pytest -q

lint:
	ruff check src examples tests
	ruff format --check src examples tests

fmt:
	ruff format src examples tests

examples:
	python examples/plain_example.py
	python examples/langchain_example.py

all: lint test examples
