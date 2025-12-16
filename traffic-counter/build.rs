use std::{
    borrow::Cow,
    env,
    ffi::OsString,
    fs,
    io::{BufRead, BufReader},
    path::PathBuf,
    process::{Child, Command, Stdio},
    thread,
};

use anyhow::{Context as _, Result, anyhow};
use aya_build::{Package, Toolchain};
use cargo_metadata::{Artifact, CompilerMessage, Message, Target};

fn main() -> anyhow::Result<()> {
    let cargo_metadata::Metadata { packages, .. } = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .context("MetadataCommand::exec")?;
    let ebpf_package = packages
        .into_iter()
        .find(|cargo_metadata::Package { name, .. }| name.as_str() == "traffic-counter-ebpf")
        .ok_or_else(|| anyhow!("traffic-counter-ebpf package not found"))?;
    let cargo_metadata::Package {
        name,
        manifest_path,
        ..
    } = ebpf_package;
    let ebpf_package = Package {
        name: name.as_str(),
        root_dir: manifest_path
            .parent()
            .ok_or_else(|| anyhow!("no parent for {manifest_path}"))?
            .as_str(),
        ..Default::default()
    };
    build_ebpf_quiet([ebpf_package], Toolchain::default())
}

fn build_ebpf_quiet<'a>(
    packages: impl IntoIterator<Item = Package<'a>>,
    toolchain: Toolchain<'a>,
) -> Result<()> {
    let out_dir = env::var_os("OUT_DIR").ok_or(anyhow!("OUT_DIR not set"))?;
    let out_dir = PathBuf::from(out_dir);

    let endian =
        env::var_os("CARGO_CFG_TARGET_ENDIAN").ok_or(anyhow!("CARGO_CFG_TARGET_ENDIAN not set"))?;
    let target = match endian.as_os_str().to_string_lossy().as_ref() {
        "big" => "bpfeb",
        "little" => "bpfel",
        other => return Err(anyhow!("unsupported endian={other}")),
    };

    const TARGET_ARCH: &str = "CARGO_CFG_TARGET_ARCH";
    let bpf_target_arch = env::var(TARGET_ARCH).unwrap_or_else(|_| panic!("{TARGET_ARCH} not set"));
    let bpf_target_arch = target_arch_fixup(bpf_target_arch.into()).into_owned();
    let target = format!("{target}-unknown-none");

    let toolchain_name: Cow<'a, str> = match toolchain {
        Toolchain::Nightly => Cow::Borrowed("nightly"),
        Toolchain::Custom(spec) => Cow::Borrowed(spec),
    };
    for Package {
        name,
        root_dir,
        no_default_features,
        features,
    } in packages
    {
        println!("cargo:rerun-if-changed={root_dir}");

        let mut cmd = Command::new("rustup");
        cmd.args([
            "run",
            toolchain_name.as_ref(),
            "cargo",
            "build",
            "--package",
            name,
            "-Z",
            "build-std=core",
            "--bins",
            "--message-format=json",
            "--release",
            "--target",
            &target,
        ]);
        if no_default_features {
            cmd.arg("--no-default-features");
        }
        if !features.is_empty() {
            cmd.args(["--features", &features.join(",")]);
        }

        const SEPARATOR: &str = "\x1f";
        let mut rustflags = OsString::new();
        for part in [
            "--cfg=bpf_target_arch=\"",
            &bpf_target_arch,
            "\"",
            SEPARATOR,
            "-Cdebuginfo=2",
            SEPARATOR,
            "-Clink-arg=--btf",
        ] {
            rustflags.push(part);
        }
        cmd.env("CARGO_ENCODED_RUSTFLAGS", rustflags);

        for key in ["RUSTC", "RUSTC_WORKSPACE_WRAPPER"] {
            cmd.env_remove(key);
        }

        let target_dir = out_dir.join(name);
        cmd.arg("--target-dir").arg(&target_dir);

        let mut child = cmd
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("failed to spawn {cmd:?}"))?;
        let Child { stdout, stderr, .. } = &mut child;

        let stderr = stderr.take().expect("stderr");
        let stderr = BufReader::new(stderr);
        let stderr_handle = thread::spawn(move || {
            for line in stderr.lines() {
                match line {
                    Ok(line) => eprintln!("[ebpf] {line}"),
                    Err(err) => eprintln!("[ebpf] failed to read stderr: {err}"),
                }
            }
        });

        let stdout = stdout.take().expect("stdout");
        let stdout = BufReader::new(stdout);
        let mut executables = Vec::new();
        for message in Message::parse_stream(stdout) {
            match message.expect("valid JSON") {
                Message::CompilerArtifact(Artifact {
                    executable: Some(executable),
                    target: Target { name, .. },
                    ..
                }) => {
                    executables.push((name, executable.into_std_path_buf()));
                }
                Message::CompilerArtifact(Artifact { .. }) => {}
                Message::CompilerMessage(CompilerMessage { message, .. }) => {
                    if let Some(rendered) = message.rendered {
                        for line in rendered.lines() {
                            eprintln!("[ebpf] {line}");
                        }
                    }
                }
                Message::TextLine(line) => {
                    eprintln!("[ebpf] {line}");
                }
                _ => {}
            }
        }

        let status = child
            .wait()
            .with_context(|| format!("failed to wait for {cmd:?}"))?;
        if !status.success() {
            return Err(anyhow!("{cmd:?} failed: {status:?}"));
        }

        stderr_handle
            .join()
            .unwrap_or_else(|err| std::panic::resume_unwind(err));

        for (name, binary) in executables {
            let dst = out_dir.join(name);
            fs::copy(&binary, &dst)
                .with_context(|| format!("failed to copy {binary:?} to {dst:?}"))?;
        }
    }

    Ok(())
}

fn target_arch_fixup(target_arch: Cow<'_, str>) -> Cow<'_, str> {
    if target_arch.starts_with("riscv64") {
        "riscv64".into()
    } else {
        target_arch
    }
}
