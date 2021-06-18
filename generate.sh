#!/bin/bash

if [ -f "testnew.sh" ]; then
rm -rf "testnew.sh"
fi

loop=$1
for i in $(seq 1 $loop)
do
num=1
x=$[RANDOM%2]
if [ $x -eq $num ];then
echo "./send.py --p TCP --src $(($RANDOM%16)) --des $(($RANDOM%16)) --m message+$i --sp $(($RANDOM%4+1)) --dp $(($RANDOM%4+1))" >> testnew.sh
else
echo "./send.py --p UDP --src $(($RANDOM%16)) --des $(($RANDOM%16)) --m message+$i --sp $(($RANDOM%4+1)) --dp $(($RANDOM%4+1))" >> testnew.sh
fi
done

chmod 777 testnew.sh
if [ -f "testnew.sh" ]; then
rm -rf "DemoLinear/testnew.sh"
rm -rf "DemoNew/testnew.sh"
fi

cp testnew.sh DemoLinear/
cp testnew.sh DemoNew/
