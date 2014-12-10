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
sed -i "s/version = .*/version = '${version}'/" docs/conf.py
sed -i "s/release = .*/release = '${version}'/" docs/conf.py
git add docs/conf.py

git commit -m "Bumped version to $version"
git push

python3 setup.py clean
python3 setup.py test

python3 setup.py sdist upload

git tag ${version}
git push --tags
