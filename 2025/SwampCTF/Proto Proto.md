## Challenge

Moto Moto likes you. But not enough to explain how his server works. We got a pcap of the client and server communicating. Can you figure out how the server works and retrieve the flag?

`proto_proto.pcap`
## Solution

Proto Proto seems to be a simple gaming platform set up. If we pay attention to the UDP datagrams sent, we'll notice that after resolving the user at `172.19.0.2`, packets are sent, with a response later that contains the strings `flag.txt` and `secret.txt.

Looking into the other UDP packets, we can notice later that a packet is send with the strings `flag.txt` and a response of `swampCTF{d1d_y0u_r34lly_7h1nk_17_w0uld_b3_7h47_345y?}`. This gave hints to the format of the message. If we walk backwards from the end of the message from the request at packet 108, we can notice before flag.txt there are two numbers, `0x02` and `0x08`. Walking back to the previous commands we can see that there are likely command codes `0x00` and `0x02`.

We send a datagram with just a `0x00` and sure enough, we get a response containing the ASCII `flag.txt`. The syntax of the other command code was likely `<cmd-code><filename-size><filename>` and so we craft the payload `0208666c61672e747874` - basically what the `pcap` did and we get a response containing the real flag:

`swampCTF{r3v3r53_my_pr070_l1k3_m070_m070}`