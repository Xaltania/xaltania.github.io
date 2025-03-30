## Challenge

Moto Moto heard you were able to reverse his server code, so he set up some "encryption". Can you figure out the key and retrieve the flag?

## Solution

To solve this challenge, I looked through the UDP packets again, similarly to Proto Proto. We can immediately notice two things: a command with code `0x01` and a change to the `0x02` syntax: `<cmd-code><`