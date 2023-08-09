# Cyber Laboratory – DDoS Attack
### For Computer Science B.Sc. Ariel University

**By Lidor Keren Yeshuah and Roy Simanovich**

## Description
In this assignment we had to build a DDoS program that spams an Apache 2 server (web-
server) with SYN packets, from different IP addresses and random source ports to port 80.
We written our program in two languages (C and Python), and compared the performance of
each one of the programs. We ran an Apache 2 server on a Docker container (10.9.0.5),
a monitor program from another Docker container (10.9.0.2) and we ran the attack from
our local machine. For each attack, we’ve measured the time it took to send each SYN
packet, the time it took for the whole attack to run, the average sending time of the
SYN packets and also, we’ve measured all those parameters for the monitor program. We
saved each data to different files, during the attack, and then we ran another program
that translated the results from plain text to a logarithmic graph. The purpose of the
monitor program is to send a ping every 5 seconds to the Apache 2 server, to see how
much the server is flooded and “busy” with the SYN attack packets. Our goal is to see
along the attack, that it’ll take more time for the Apache 2 server to response to the
monitor’s ping (and in generally, for other requests), and we expect to see the RTT grow
overtime since the server is flooded (basically that’s what DDoS does).

## Requirements

* Full linux (Ubuntu 22.04 LTS recommended)
* Python 3.10
* GNU C Compiler
* Docker-Compose (latest version)

We highly recommend using Dockers in order to run the program.
Using Dockers will allow you to run the program on few different machines on a single machine.

## Installation

1. First, install Docker-Compose:
You can find the installation instructions here: https://linuxhint.com/install-docker-compose-ubuntu-22-04/

2. Open a new Directory in your computer.
3. Paste the attached "docker-compose.yml" file in your new directory.
Note: Do not change the docker-compose.yml file contents unless you know what you are doing. 
4. Open a new subdirectory in your new directory named "volumes".
5. Paste the attached files in your new subdirectory - "volumes".
6. move the file that you want to send to the server through our data-diode to the "volumes" subdirectory.

## Running (Linux)
1. open 5 terminals and navigate to your new subdirectory.
2. In the first terminal, run the following command:
```bash
sudo docker-compose up
```
3. In the 4 other terminals, run the following command to enter each container's shell:
```
sudo docker exec -it <container-id> /bin/bash
```
then, enter the "volume" directory in each container:
```bash
cd volumes
```

4. In each container, run the following command to run the program:
```bash
python3 <program-name>.py
```
run the write command according to the container you are in:
for example, if you are in the enduser container, run the following command:
```bash
python3 enduser.py
```

If you want to see which containers are currently alive, run the following command:
```bash
sudo docker ps -a
```

In order to exit the docker, just type "exit" in the shell.
In order to stop all the dockers, press ctrl+c in the terminal you ran the "sudo docker-compose up" command.


## Running (Linux)
On your brand new dockers run the following commands:
```bash
# Build all the C files
make

# Ping check
./Ping <ip>

# Run the attack in C version
./Attacker <ip>

# Run the attack in python version
python3 attack.py

# Generate the graphs for each attack
python3 generate_grapgh.py
```
