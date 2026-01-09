.PHONY: install

install:
	uv build
	uv tool install dist/*.whl --force