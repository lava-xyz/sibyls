#!/bin/bash

ps cax | grep sibyls > /dev/null
if [ $? -ne 0 ]; then
    nohup /home/ubuntu/sibyls/target/release/sibyls -s /home/ubuntu/sibyls/secret.txt &
fi
