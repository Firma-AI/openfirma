.PHONY: install run

-include .env
export

install:
	uv sync

run:
	uv run python -m agent.main
