# Introduction, exploting the device for fun and profit

(disclamer: I knew next to nothing about arm v7 assembler and/or ghydra, this is more a how not to do things than anything else. But I think it can be a good starting point for someone starting a similar journey. )

I've found a couple of mistAP 41 in an e-waste facility, this model is reaching EOL, and in a few months I bet there will be more avaible in second hand markets and trash containers are all over the worrld. This device is based on ... , and I hope that is similar enough to the cisco meraki platfrom, recently supported in openwrt:
https://openwrt.org/toh/meraki/mx65w 

This device has 3 PCI BCM43465 wireless cards - wich I don't know the state of the current drivers but in general there's no good open source support for them - in an interesting configuration. One of the cards is on a standard mini-PCI socket (put a supported card and you have a very capable AP, profit!), the other two are connected to one mini PCI socket on a custom PCB. There's a PCI swith on the device, the custom PCB just has 2 standard BCM43465 cards on metalic shields for the glory of the FCC and other agencies. I haven't tried connecting one standard card there yet, but it will be easy enough to design a PCB with 2 standard mini PCI sockets, there's no extra circuitery on that board.

All of this, combined with the info from https://github.com/neggles/mist-ap41 makes for a very interesting target. I was lucky and after only a few minutes of ghydra poking the u-boot binary from neggle's repo, I found out  that the challenge autentification was not really implemented in one of the uboot copies.   

So in a way, this is an exercise in futality. Once stablished that the answer to the TODO challenge it's just 'B' (it's ok to laugh, I couldn't believe it myself), we already own the device anyway, as mist left a very capable copy (we can dump and write the eeprom, tftp boot and many other goodies). So why all of this you may ask?, the short answer is that I need different hobbies, get out and socilice more.  

# Picking the right target

In the device's ubidump files, the inittab file tell us that serial console it's gardded by the binary console_login. To start with, we can use check if there are some readable strings on the binary, strings is your friend for this (strings console_login):
```
true
%s: no memory
developer
%s: bytes2base64 failed
challenge: %s
response: 
%s: error reading response: %s
Cm7nkp2X4cMfKuw0
fqxWAIytIQt26vkU
If you want this to be permanent set
 developer=%s
in uboot env
successful developer-mode console login
success
test
Usage: %s [-t] <username>
%s: can't parse option %c
manufacturing
mfg_magic
successful console login
regulatory
can't create socket: %s
/tmp/ep-control-proxy
can't open ep-ctrl: %s
console login attempt
%s: no EPID
failed developer-mode console login
failure
Incorrect response
sr7Krl7tkajVBowS
ZuSX01QGh8PJq0Na
/bin/login
exec failed: %s
failed console login
aeabi
Cortex-A9
```   
