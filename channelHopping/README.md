# Normal version (does not have the adaptive feature)
## Compile
gcc channel_hopping.c -o channel_hopping
## Run with 
sudo ./channel_hopping "interface"
# Adaptive feature
Basically, we will stay on the channel having the higher traffic rate for longer
## Idea
After "RECALIBRATION_INTERVAL" the system will re-calibate itself by counting the received packages on every channel for 0.5s, so the total time for calibration is 7 seconds. So after calibartion, it will change the channel & dwell time according to the number of packages received, which translates to more packet - more percent dwell time (for an interval of TOTAL_INTERVAL time) 
## HOTFIX Nov8 9:53PM
`pcap_loop()` wont respond when there is no traffic on the channel, fixed by using `pcap_dispatch()` as an alternative. For more details please refer to [pcap man page](https://linux.die.net/man/3/pcap_dispatch)
## Compile & Run
+ This program uses libpcap-dev package, so in order to build & run. Run `sudo apt install libpcap-dev` in your terminal
+ `make all` to build
+ `sudo ./adaptive_channel_hopping <interface>` to run
Tested on Ubuntu 22.04 LTS w/ kernel version 6.x :shipit:
