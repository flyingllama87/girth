# girth Go implementation

This branch contains the original Go implementation of girth, an Aspera
FASP-inspired bulk file transfer protocol for Long Fat Networks.

The public `main` branch is the Rust implementation. This Go branch is kept as
the reference implementation for the original wire protocol and for comparison
with the Rust port.

## Build

```sh
make
make test
make check
```

Or use the Go toolchain directly:

```sh
go build ./...
go test ./...
```

The CLI lives under `cmd/girth`.

## Simple Example

Run a server:

```sh
girth server -addr :7400 -dir /data
```

Push a file:

```sh
girth send -rate 800 bigfile.bin server.example:7400
```

Pull a file:

```sh
girth recv -rate 800 server.example:7400 bigfile.bin ./bigfile.bin
```

Add `-encrypt` on client commands if you want encrypted DATA payloads.

## Network Requirements

girth uses a TCP control channel and a UDP data channel.

| Channel | Protocol | Direction | Purpose |
|---|---|---|---|
| Control | TCP | client to server | handshake, file metadata, negotiated UDP port, optional key exchange |
| Data | UDP | bidirectional | file DATA, receiver START, FEEDBACK/NACKs, FIN |

The server needs an inbound TCP control port. The default CLI port is `7400`,
set with `girth server -addr :7400`.

For each transfer, the receiver binds a UDP data socket and advertises that port
over the TCP control channel. With the Go server defaults this is an ephemeral
UDP port, so firewalls need to allow the UDP data port as well as the TCP control
port.

## Notes

- This branch is wire-compatible with the Rust `main` branch as of the public
  split.
- Optional data-plane encryption is supported with `-encrypt`.
- Linux is the best-tested platform for throughput.
- Keep wire-format changes synchronized with Rust if this branch is updated.

See `LESSONS.md` and `MTU.md` for protocol and operational notes.

## License

MIT.
