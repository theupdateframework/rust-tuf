.PHONY: init run
.DEFAULT_GOAL := run


init: venv
	. venv/bin/activate && \
	pip install -Ur requirements.txt

run: init
	. venv/bin/activate && \
	./repo-maker.py -o ../tests/repo-1/

venv:
	@virtualenv -p $(which python3) venv
