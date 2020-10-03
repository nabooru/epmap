# epmap.c

An endpoint mapper is a service on a remote procedure call (RPC) server that maintains a database of dynamic endpoints and allows clients to map an interface/object UUID pair to a local dynamic endpoint. This trivial tool can be used to identify services that have registered with DCE/RPC endpoint mapper. Usage: epmap [-p port] hostname.
