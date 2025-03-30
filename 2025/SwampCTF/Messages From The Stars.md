## Challenge

We recently detected this signal from deep space, we aren't quite sure what to make of it but we suspect it originated from intelligent life. Want to take a crack at decoding it?

`message_from_the_stars.wav`

## Solution
When it comes to audio, there are many ideas that come to mind, however, the challenge was simply two frequencies. I could immediately rule out Dual-Tone Multi-Frequency, dial-up, modems etc.

As a producer, it's pretty easy to extract frequencies and rhythms from an audio file, so I quickly plopped the file into FLStudio (rather than writing a script) and identified that the audio file was consistently playing sounds at 900Hz and 1100Hz. We could just double confirm this by plotting the frequency throughout the entire file.

![graph.png.png]

It was beeping at around 13 per second, with this info we could write a quick script and transform the audio into a binary stream. I tried a couple things with the output, to no avail. Then I suddenly recalled an audio file from a video I saw in high school, the [Arecibo Message](https://archive.org/details/the-arecibo-message) which was essentially a message sent to the cosmos to broadcast our existence.

I thought it had to be connected, since it's literally "Messages From The Stars", so I tried encoding the bytes as colours and formed a bitmap, it did not work. By a stroke of luck, I put on my girlfriend's glasses to fiddle and at a distance, I noticed it: the ASCII art. I quickly transformed the 0's and 1's into `.` and `█`s and the result was
![block_star_jumbled.png.png]
Write another bash script to vary the width and:
![flag.png.png]
