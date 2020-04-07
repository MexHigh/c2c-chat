# c2c Chat Tool in Go (c2c = client to client)

This tool was my first project in go to play with goroutines (here: Message receiving routine, so you can send AND receive messages at the same time).
It uses my self-implemented RSA, WHICH IS NOTE SAFE (https://git.leon.wtf/leon/encryption-in-go).

# How it works

First you need to generete yourself a RSA key pair (the client can do this for you). Your Chat partner has to do that too.
Now you can exchange your public keys (the client can do this also via an unencrypted socket).
After that, you can establish the connection (please note, that the serving chat partner has to open the server port he has chosen in his firewall).
c2c is able to receive and send messages at the same time without waiting. Type "quit" to exit the chat.