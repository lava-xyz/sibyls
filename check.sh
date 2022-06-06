#!/bin/bash

ps cax | grep sybils > /dev/null
if [ $? -ne 0 ]; then
    ~/sybils/target/release/sybils -s ~/sybils/secret.txt &
fi