#!/bin/bash

python3 -m coverage run -p -m pytest -rsfEx || exit $?

python3 -m coverage combine

python3 -m coverage report -m
exit $?
