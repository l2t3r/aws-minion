flake8:
	python3 setup.py flake8

test:
	python3 setup.py test --cov-html=yes

clean:
	rm -rf *.egg*
	rm -rf dist
	rm -rf build
	rm -rf htmlcov
