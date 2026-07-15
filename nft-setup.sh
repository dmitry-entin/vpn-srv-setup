#!/bin/bash

nft 'add table inet filter; add chain inet filter output { type filter hook output priority 0; }; add rule inet filter output tcp flags & (syn|ack) == syn|ack tcp sport 443 limit rate over 1/second burst 1 packets drop'
