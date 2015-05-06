# SecureMessaging
Secure messaging system for Computer Networking course. Bob acts as the server while Alice is the client. After handshake and authentication, Alice can send secure messages to Bob.

To use on CADE machines, use the following command: 

	python27 Bob.py

	python27 Alice.py

Accepts the following command-line arguments

	-h Help, displays list of acceptable arguments

	-r [hostname] Specify which host to connect/run on.

	-p [port] Specifiy which port the program will run on.

	-k [key] for providing a passphrase for encryption (only Alice.py accepts this argument)
