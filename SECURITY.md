# Security

sot authenticates one upload with a short passcode. It does not encrypt the connection. Anyone who can read the packets can read the file and the passcode. Use it on a network you trust, or inside a tunnel you already trust.

The passcode is printed only on the receiver. Share it out of band. A wrong 8-character code closes the port. A code of any other length is rejected before the sender connects.

Do not bind this to a public address and leave it running. The default listen address is every IPv4 interface on the chosen port, for one attempt only.

Report a vulnerability through GitHub private vulnerability reporting on this repository. Do not put exploit details in a public issue. If private reporting is not enabled yet, contact the maintainer directly instead of filing a public issue.
