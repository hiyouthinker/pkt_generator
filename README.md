# pkt_generator
packet generator

# 1 Introduction
```
libdebug.c is the basic library, and other .c files are functional modules 
```
# 2 compile & run
```
example:
  gcc libdebug.c ip_client.c -o ip_client
```
```
./ip_client -h
Copyright: Version 2.0 @BigBro/2020
Usage: ./ip_client
	-H <HOST>              dst ip
	-l <LOCAL>             src ip
	-D <PORT>              dst port
	-s <NUMBER>            sleep time
	-z <NUMBER>            UDP data length (0 =< SIZE <= 1500)
	-p <NUMBER>            l4 protocol
	-c <COUNT>             count
	-r                     read from peer
	-m                     src ip is random
	-d                     debug switch
	-h                     Show This
```
```
./ip_client -H 172.16.132.1 -D 80 -r -dddd
```
