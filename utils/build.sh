#!/bin/bash

python3 -m mpy_cross device/boot.py
python3 -m mpy_cross device/main.py
python3 -m mpy_cross device/third_party

