extern crate getopts;
use getopts::Options;
use std::{env, io, thread};
use std::borrow::Borrow;
use std::fs::File;
use std::cell::RefCell;
use std::io::Write;
use std::sync::{Arc, Mutex};
use std::sync::atomic::Ordering;
use sha2::{Sha256, Digest};
use jwalk::{Parallelism, WalkDir};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use rayon::prelude::*;
use terminal_size;

struct Args {
    source_dir: String,
    target_dir: String,
    output_file: String,
}

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} FILE [options]", program);
    print!("{}", opts.usage(&brief));
}

fn print_banner() {
    println!("============\nBackup Auditor v0.1.0\n============\n")
}

fn main() {
    print_banner();
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();

    let mut opts = Options::new();
    opts.optopt("s", "", "set the source directory (required)", "SOURCE");
    opts.optopt("t", "", "set the target directory (required)", "TARGET");
    opts.optopt("o", "", "output filename (required)", "OUTPUT");
    opts.optflag("h", "help", "print this help menu");

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => { m }
        Err(f) => { panic!("{}", f.to_string()) }
    };

    if matches.opt_present("h") {
        print_usage(&program, opts);
        return;
    }

    match (matches.opt_present("s"), matches.opt_present("t"), matches.opt_present("o")) {
        (true, true, true) => { }
        (_, _, _) => {
            print_usage(&program, opts);
            return;
        }
    }

    let parsed_args = Args {
        source_dir: {
            let m = matches.opt_str("s").unwrap();
            m.strip_suffix("/").unwrap_or(m.borrow()).to_string()
        },
        target_dir: {
            let m = matches.opt_str("t").unwrap();
            m.strip_suffix("/").unwrap_or(m.borrow()).to_string()
        },
        output_file: matches.opt_str("o").unwrap(),
    };

    println!("Source directory: {:?}\nTarget directory: {:?}\nOutput filename: {:?}", parsed_args.source_dir, parsed_args.target_dir, parsed_args.output_file);

    deep_check(parsed_args);
}

fn deep_check(args: Args) {

    let output_file = match File::create(args.output_file) {
        Ok(o) => {
            Arc::new(Mutex::new(o))
        }
        Err(e) => {
            panic!("Failed to create output file {:?}", e)
        }
    };

    let mut files_count: u64 = 0;
    for _ in WalkDir::new(&args.source_dir) {
        files_count += 1;
    }

    static BAR_COUNT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

    let mbar: MultiProgress = MultiProgress::new();

    let bars: Vec<ProgressBar> = (0..=num_cpus::get())
        .map(|_| {
            let x = ProgressBar::new_spinner();
            let s = ProgressStyle::default_spinner().tick_strings(&[
                "|",
                "/",
                "-",
                "\\",
            ]);
            x.set_style(s);
            mbar.add(x)
        })
        .collect();

    let pbar = mbar.add(ProgressBar::new(files_count));

    thread_local! {
        static LOCAL_BAR_ID: RefCell<usize> = {
            let x = BAR_COUNT.fetch_add(1, Ordering::SeqCst);
            RefCell::new(x)
        }
    }

    let walk_thread = thread::spawn(move || {
        WalkDir::new(&args.source_dir)
            .parallelism(Parallelism::RayonNewPool(0))
            .into_iter()
            .par_bridge()
            .for_each(|src_entry| {
                let src_path = src_entry.unwrap().path().display().to_string();
                let stripped_path = src_path.strip_prefix(&args.source_dir).unwrap();

                let tgt_path = format!("{}{}", args.target_dir, stripped_path);

                let src_r = File::open(&src_path);
                let tgt_r = File::open(&tgt_path);

                match (src_r, tgt_r) {
                    (Ok(src), Ok(tgt)) => {
                        LOCAL_BAR_ID.with(|bid| {
                            let x = bid.borrow().clone();
                            let b = bars[x].borrow();
                            let term_width = terminal_size::terminal_size().map(|s| usize::from((s.0.0-5).max(0))).unwrap_or(80);
                            b.set_message(format!("{}", trim_str(&tgt_path, term_width)));
                            cmp_files(&output_file, &src_path, &src, &tgt_path, &tgt);
                            pbar.inc(1);
                        });
                    }
                    (Ok(_), Err(tgt)) => {
                        output_file
                            .lock()
                            .unwrap()
                            .write_all(format!("Found missing file in target\nsrc={:?}\ntgt={:?}\nReason:{:?}\n", src_path, tgt_path, tgt).as_bytes()).unwrap();
                    }
                    (Err(src), Ok(_)) => {
                        output_file
                            .lock()
                            .unwrap()
                            .write_all(format!("Found missing file in source\nsrc={:?}\ntgt={:?}\nReason:{:?}\n", src_path, tgt_path, src).as_bytes()).unwrap();
                    }
                    (Err(src), Err(tgt)) => {
                        output_file
                            .lock()
                            .unwrap()
                            .write_all(format!("Found missing file in source and target\nsrc={:?}\ntgt={:?}\nSrcReason:{:?}\nTgtReason:{:?}\n", src_path, tgt_path, src, tgt).as_bytes()).unwrap();
                    }
                }
            });

        bars.iter().for_each(|b| {
            b.finish()
        });
    });

    mbar.join().unwrap();

    walk_thread.join().expect("failed to join walk thread");
}


fn cmp_files(output_file: &Arc<Mutex<File>>, src_path: &String, mut src: &File, tgt_path: &String, mut tgt: &File) -> () {
    let src_meta = src.metadata().unwrap();
    let tgt_meta = tgt.metadata().unwrap();
    if src_meta.is_dir() && tgt_meta.is_dir() {
        return;
    } else if src_meta.is_symlink() && tgt_meta.is_symlink() {
        return;
    } else if src_meta.is_file() && tgt_meta.is_file() {
        let mut src_hasher = Sha256::new();
        let _ = io::copy(&mut src, &mut src_hasher).unwrap();
        let src_hash = src_hasher.finalize();

        let mut tgt_hasher = Sha256::new();
        let _ = io::copy(&mut tgt, &mut tgt_hasher).unwrap();
        let tgt_hash = tgt_hasher.finalize();

        if src_hash != tgt_hash {
            output_file
                .lock()
                .unwrap()
                .write_all(format!("Found mismatched sha256 hashes:\nsrc={:?}\n{:?}\ntgt={:?}\n{:?}\n", src_path, src_hash, tgt_path, tgt_hash).as_bytes()).unwrap()
        }
    } else {
        output_file
            .lock()
            .unwrap()
            .write_all(format!("Found mismatched file types\nsrc={:?}\ntgt={:?}\n", src_path, tgt_path).as_bytes()).unwrap()
    }
}

fn trim_str(str: &String, width: usize) -> String {
    let mut len = str.len();
    let c2 = str.chars().skip_while(|_|{
        len = len-1;
        len > width
    });
    String::from_iter(c2)
}
