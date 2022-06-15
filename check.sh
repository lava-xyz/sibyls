#!/bin/bash

ps cax | grep sybils > /dev/null
if [ $? -ne 0 ]; then
    nohup /home/ubuntu/sybils/target/release/sybils -s /home/ubuntu/sybils/secret.txt &
fi
