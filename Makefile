.PHONY: all
all: venv

venv:
	virtualenv venv -ppython3
	venv/bin/pip install -r requirements.txt

clean:
	rm -rf venv/
