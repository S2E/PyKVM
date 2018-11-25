#!/bin/sh
# Copyright (c) 2018, Cyberhaven
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

# This script helps building and uploading the package to pypi.
# Instructions on https://packaging.python.org/tutorials/packaging-projects/

if [ $# -ne 1 ]; then
  echo "Usage: $0 [test|prod]"
  exit
fi

TARGET="$1"

rm -rf dist *.egg-info s2e-out* s2e-last

python -m pip install --user --upgrade setuptools wheel
python -m pip install --user --upgrade twine

python setup.py sdist bdist_wheel

if [ "$TARGET" = "test" ]; then
  # Upload to test repo
  twine upload --repository-url https://test.pypi.org/legacy/ dist/*
elif [ "$TARGET" = "prod" ]; then
  # Upload to real repo
  twine upload dist/*
fi
