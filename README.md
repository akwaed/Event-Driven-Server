# Event-Driven-Server-
implementing a multiplexing server to provide a simple "squaring" service

The client opens a connection to the server and sends first. Messages from the client consist of
one or more ASCII-encoded decimal numbers (i.e., byte values between 0x30 and 0x39, inclusive)
separated by a single byte with the value 0x19.
Transmitted numbers may be positive or negative (the latter beginning with ’-’, byte value 0x2d),
but must be between −3037000499 and 3037000499, inclusive. Numbers in this range have squares
that can be represented as a 64-bit 2’s complement value (i.e., fit in a long variable).
The final value sent by the client MAY be terminated by End-of-File (EOF). That is, the server
must be prepared to receive EOF (i.e., recv() returns 0) after a valid input number.
