## Challenge

Moto Moto heard you were able to reverse his server code, so he set up some "encryption". Can you figure out the key and retrieve the flag?

## Solution

To solve this challenge, I looked through the UDP packets again, similarly to Proto Proto. We can immediately notice two things: a command with code `0x01` and a change to the `0x02` syntax: `0x02<pw-length><pw><filename-length><filename>`

I noticed that `0x01<password>` had response codes, with `super_secret_password` giving a unique response from the rest. I tried requesting the files using this passcode but it returned junk. I played with the responses but nothing legible came out.

I tried querying to see if the server had a `secret.txt` like the `pcap` from the first challenge to no avail. Eventually I started throwing strings at the two file that it did return, which are `flag.txt` and `real_flag.txt`. I received interesting responses from flag.txt, any string containing `swampCTF` returned responses "i_do_rea..." and then junk. Noticing it was likely a simple XOR encryption, I tested out keywords, with `swampCTF{m070_m070_...` returning `i_do_real_encryption...` followed by junk.

Why not send that in?
`0x02i_do_real_encryptionflag.txt`

-->

 `swampCTF{m070_m070_54y5_x0r_15_4_n0_n0}`