# gdb-protocol

An implementation of the [GDB Remote Serial
Protocol](https://sourceware.org/gdb/onlinedocs/gdb/Remote-Protocol.html),
in rust.

The library consists of building blocks that let you make your own I/O
for the protocol, such as `parser::Parser`, or use the high-level
`GdbServer` structure which lets you easily work on more simple,
blocking I/O. This modularity allows for full flexibility, while still
leaving the most common use-cases simple.

The project was created to allow creating a GDB server for Redox OS.
