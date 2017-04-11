.PHONY: init
.DEFAULT_GOAL := init


init: venv
	. venv/bin/activate && \
	pip install -Ur requirements.txt

venv:
	@virtualenv -p $(which python3) venv
