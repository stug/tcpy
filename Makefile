.PHONY: all
all: venv

venv:
	virtualenv venv -ppython3.7

clean:
	rm -rf venv/
