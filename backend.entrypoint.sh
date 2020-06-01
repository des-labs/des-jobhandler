#!/bin/bash

if [[ "$LOCAL_DEV" == "true" ]]; then
	pip3 install --user -r requirements.txt
fi

python3 main.py
