#!/bin/bash
echo "EncryptDecryptGUI application started as background proccess..."
nohup java -cp "bin:" EncryptDecryptGUI > /dev/null &
