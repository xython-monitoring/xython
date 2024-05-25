#!/bin/bash

python3 -m coverage run -p -m pytest
exit $?
