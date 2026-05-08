.PHONY: install run demo-scripted

-include .env
export

install:
	uv sync

run:
	uv run python -m agent.main

demo-scripted:
	uv run python -m agent.scripted
