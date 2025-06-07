#!/bin/bash
sudo lsof -t -i :12345 | xargs kill