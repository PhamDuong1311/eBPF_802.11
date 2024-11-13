# eBPF802.11
An eBPF program to capture raw 802.11 frames
## Dependencies
Working with 5.15 & upstream mainline kernel
Please refer to [this](https://github.com/lizrice/learning-ebpf) to install the needed packages
## Usage
Every machine have different radio tap header length, make sure to change what fit yours in hello.bpf.c file
Different NIC have different name, use iwconfig and change to yours in start.sh and stop.sh files
Remember to bring your NIC to monitor mode by using [airmon-ng](https://github.com/aircrack-ng/aircrack-ng)
In your terminal
```python

# build the project
sudo make
# start capturing
sudo ./start.sh

# stop capturing
sudo ./stop.sh
```
## Contributing
This project is maintained by me & @PhamDuong1311, checking out his [github](https://github.com/PhamDuong1311)
Please make sure to update tests as appropriate.

## License

[MIT](https://choosealicense.com/licenses/mit/)
