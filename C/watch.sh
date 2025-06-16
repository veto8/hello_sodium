#!/bin/bash

# apt-get install inotify-tools
while true; do
      inotifywait -e modify "main.c"
      make linux
      ./hello_sodium_linux
    done
