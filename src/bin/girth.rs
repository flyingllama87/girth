//! Command `girth`: a CLI client/server for the girth bulk transfer protocol.

use girth::{client_recv, client_send, default_params, Server, TransferParams, DEFAULT_BLOCK_SIZE};
use std::process::exit;
use std::time::Duration;

fn usage() {
    eprint!(
        "girth - FASP-inspired LFN file transfer (Rust)

commands:
  girth server [flags]                          run a server
  girth send   [flags] <file> <host:port>       push a file to a server
  girth recv   [flags] <host:port> <name> <out> pull a file from a server

flags:
  -rate <Mbps>      target injection rate (default 100)
  -max <Mbps>       max injection rate (default 10000)
  -alpha <Mbps>     adaptive adaptation factor (default 30)
  -adaptive         use delay-based adaptive rate control
  -encrypt          encrypt the data plane (X25519 + AES-GCM/ChaCha20-Poly1305)
  -block <bytes>    UDP payload block size (default {})
  -workers <n>      disk/ingest worker threads (0=auto)
  -fb <us>          feedback/NACK interval (microseconds, default 5000)
  -report <ms>      stats report interval (ms; 0=off, default 1000)
  -addr <host:port> server: TCP control listen address (default :7400)
  -dir <path>       server: directory to serve/store files (default .)
",
        DEFAULT_BLOCK_SIZE
    );
}

struct Parsed {
    params: TransferParams,
    addr: String,
    dir: String,
    positionals: Vec<String>,
}

fn parse(args: &[String]) -> Result<Parsed, String> {
    let mut p = default_params();
    let mut rate_mbps = 100.0f64;
    let mut max_mbps = 10000.0f64;
    let mut alpha_mbps = 30.0f64;
    let mut report_ms = 1000i64;
    let mut addr = ":7400".to_string();
    let mut dir = ".".to_string();
    let mut positionals = Vec::new();

    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if let Some(flag) = a.strip_prefix('-') {
            let (name, inline_val) = match flag.split_once('=') {
                Some((n, v)) => (n, Some(v.to_string())),
                None => (flag, None),
            };
            let is_bool = matches!(name, "adaptive" | "encrypt");
            let value = if is_bool {
                None
            } else if let Some(v) = inline_val {
                Some(v)
            } else {
                i += 1;
                if i >= args.len() {
                    return Err(format!("flag -{} needs a value", name));
                }
                Some(args[i].clone())
            };
            let num = || -> Result<f64, String> {
                value
                    .as_ref()
                    .unwrap()
                    .parse::<f64>()
                    .map_err(|_| format!("flag -{}: invalid number", name))
            };
            match name {
                "rate" => rate_mbps = num()?,
                "max" => max_mbps = num()?,
                "alpha" => alpha_mbps = num()?,
                "adaptive" => p.adaptive = true,
                "encrypt" => p.encrypt = true,
                "block" => p.block_size = num()? as usize,
                "workers" => p.read_workers = num()? as usize,
                "fb" => p.feedback_interval_us = num()? as u32,
                "report" => report_ms = num()? as i64,
                "addr" => addr = value.unwrap(),
                "dir" => dir = value.unwrap(),
                "procs" => {}
                "h" | "help" => {
                    usage();
                    exit(0);
                }
                _ => return Err(format!("unknown flag -{}", name)),
            }
        } else {
            positionals.push(a.clone());
        }
        i += 1;
    }

    p.rate_bps = (rate_mbps * 1e6) as u64;
    p.max_bps = (max_mbps * 1e6) as u64;
    p.alpha_bps = (alpha_mbps * 1e6) as u64;
    p.report_interval = if report_ms > 0 {
        Duration::from_millis(report_ms as u64)
    } else {
        Duration::from_secs(3600)
    };

    Ok(Parsed {
        params: p,
        addr,
        dir,
        positionals,
    })
}

fn main() {
    let argv: Vec<String> = std::env::args().collect();
    if argv.len() < 2 {
        usage();
        exit(2);
    }
    let cmd = argv[1].as_str();
    let rest = &argv[2..];

    if matches!(cmd, "-h" | "--help" | "help") {
        usage();
        return;
    }

    let parsed = match parse(rest) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{}", e);
            exit(2);
        }
    };
    let stop = girth::sys::install_termination_handler();

    let result = match cmd {
        "server" => {
            let srv = Server {
                addr: parsed.addr.clone(),
                dir: parsed.dir.clone(),
                params: parsed.params,
            };
            srv.listen_and_serve(stop)
                .map_err(|e| format!("server error: {}", e))
        }
        "send" => {
            if parsed.positionals.len() != 2 {
                eprintln!("usage: girth send [flags] <file> <host:port>");
                exit(2);
            }
            client_send(
                &parsed.positionals[1],
                &parsed.positionals[0],
                &parsed.params,
                stop,
            )
            .map_err(|e| format!("send error: {}", e))
        }
        "recv" => {
            if parsed.positionals.len() != 3 {
                eprintln!("usage: girth recv [flags] <host:port> <name> <out>");
                exit(2);
            }
            client_recv(
                &parsed.positionals[0],
                &parsed.positionals[1],
                &parsed.positionals[2],
                &parsed.params,
                stop,
            )
            .map_err(|e| format!("recv error: {}", e))
        }
        other => {
            eprintln!("unknown command {:?}\n", other);
            usage();
            exit(2);
        }
    };

    if let Err(e) = result {
        eprintln!("{}", e);
        exit(1);
    }
}
