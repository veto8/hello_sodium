#!/bin/bash

# apt-get install inotify-tools
while true; do
      inotifywait -e modify "main.c"
      make linux
      ./main_linux
      sleep 2
      cp output.txt ../decrypt/
done
