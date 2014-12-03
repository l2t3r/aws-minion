.PHONY: docs

flake8:
	python3 setup.py flake8

test:
	python3 setup.py test --cov-html=yes

docs:
	python3 setup.py docs

clean:
	rm -rf *.egg*
	rm -rf dist
	rm -rf build
	rm -rf htmlcov
