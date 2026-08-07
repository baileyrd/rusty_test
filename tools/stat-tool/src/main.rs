//! Reference tool 1: lists a directory and stats each entry through a
//! contract-scoped `FsRoot`. Exercises the filesystem primitive only —
//! no process spawn, no PTY.
//!
//! Also the first place the path boundary is visible. Everything this tool
//! accepts must be a `ScopedPath`, so a non-portable spelling is refused
//! with the contract's own error rather than guessed at. There is
//! deliberately no translation of user input yet — `/c/Users`-style
//! spellings are a later, typed API, not a string rewrite here.

use compat::{NativeCapabilities, Workspace};
use contract::{FsRoot, ScopedPath};

fn main() -> anyhow::Result<()> {
    let ws = Workspace::open_ambient(std::path::Path::new("."))?;
    println!("capabilities: {:?}", NativeCapabilities::detect());

    let Some(arg) = std::env::args().nth(1) else {
        print_listing(ws.read_dir_root()?);
        return Ok(());
    };

    // The boundary: an unportable spelling stops here, named.
    let path = match ScopedPath::new(&arg) {
        Ok(path) => path,
        Err(e) => {
            eprintln!("stat-tool: {e}");
            eprintln!(
                "  paths are `/`-separated and relative to the current directory; \
                 drive letters, `\\`, `:` and `..` are not portable spellings"
            );
            std::process::exit(2);
        }
    };

    let meta = ws.stat(&path)?;
    if meta.is_dir {
        print_listing(ws.read_dir(&path)?);
    } else {
        println!(
            "{path}: {} bytes, readonly={}, native={}",
            meta.len,
            meta.readonly,
            ws.canonicalize(&path)?.display_for_humans()
        );
    }
    Ok(())
}

fn print_listing(entries: Vec<contract::DirEntryInfo>) {
    println!("{:<32} {:>10} {:>6} {:>6}", "name", "bytes", "dir", "link");
    for entry in entries {
        println!(
            "{:<32} {:>10} {:>6} {:>6}",
            entry.name, entry.metadata.len, entry.metadata.is_dir, entry.metadata.is_symlink
        );
    }
}
