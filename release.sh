#!/bin/sh

if [ $# -ne 1 ]; then
    >&2 echo "usage: $0 <version>"
    exit 1
fi

set -xe

python3 --version
git --version

version=$1

sed -i "s/__version__ = .*/__version__ = '${version}'/" aws_minion/__init__.py
git add aws_minion/__init__.py

printf ${version} > VERSION
git add VERSION

git commit -m "Bumped version to $version"

python3 setup.py clean
python3 setup.py test

python3 setup.py sdist

git tag ${version}
git push --follow-tags

python3 setup.py upload
