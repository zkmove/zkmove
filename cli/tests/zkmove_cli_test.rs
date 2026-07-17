// Copyright (c) zkMove Authors

//! End-to-end test that follows the exact workflow documented in
//! `docs/user/circuit-and-proof.md`:
//!
//! 1. `zkmove vm compile --package-path ./ --skip-fetch-latest-git-deps`
//! 2. `zkmove vm run --module-id 0x1::fibonacci --function-name test_fibonacci --args 10u64`
//! 3. `zkmove vm setup` (Option 1: from the entry function)
//! 4. `zkmove vm setup --witness <witness>` (Option 2: from a witness, with --pubs-indices)
//! 5. `zkmove vm prove --args 10u64`
//! 6. `zkmove vm verify --pubs-path <instance> --proof-path <proof>`
//!
//! The test copies `cli/example` into a temp directory so that generated
//! artifacts do not pollute the repository.

use std::path::{Path, PathBuf};
use std::process::Command;

fn zkmove_bin() -> &'static str {
    env!("CARGO_BIN_EXE_zkmove")
}

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Recursively copy a directory.
fn copy_dir_all(src: &Path, dst: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let to = dst.join(entry.file_name());
        if ty.is_dir() {
            copy_dir_all(&entry.path(), &to)?;
        } else {
            std::fs::copy(entry.path(), &to)?;
        }
    }
    Ok(())
}

/// Run a `zkmove` command and assert it succeeds, echoing output on failure.
fn run_zkmove(args: &[&str], cwd: &Path) {
    let output = Command::new(zkmove_bin())
        .args(args)
        .current_dir(cwd)
        .output()
        .expect("failed to launch zkmove");
    assert!(
        output.status.success(),
        "`zkmove {}` failed\nstdout:\n{}\nstderr:\n{}",
        args.join(" "),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

/// Find the single newest file in `dir` matching prefix/extension.
fn find_latest_file(dir: &Path, prefix: &str, ext: &str) -> PathBuf {
    let mut matches: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("cannot read {}: {}", dir.display(), e))
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.starts_with(prefix) && n.ends_with(ext))
                .unwrap_or(false)
        })
        .collect();
    matches.sort();
    matches
        .pop()
        .unwrap_or_else(|| panic!("no {}*{} file found in {}", prefix, ext, dir.display()))
}

#[test]
fn circuit_and_proof_doc_workflow() {
    // Copy the example package into a temp dir, as the doc assumes running
    // from the package root and writes artifacts under it.
    let tmp = tempfile::tempdir().expect("create temp dir");
    let pkg = tmp.path().join("example");
    copy_dir_all(&manifest_dir().join("example"), &pkg).expect("copy example package");

    let params = manifest_dir().join("params").join("kzg_bn254_12.srs");
    assert!(params.is_file(), "SRS file missing: {}", params.display());
    let params = params.to_str().unwrap();

    // Step 1: compile (equivalent to `move build`).
    run_zkmove(
        &[
            "vm",
            "compile",
            "--package-path",
            "./",
            "--skip-fetch-latest-git-deps",
        ],
        &pkg,
    );
    assert!(
        pkg.join("build").join("example").is_dir(),
        "compile did not produce build output"
    );

    // Step 2: run the entry function to generate a witness.
    run_zkmove(
        &[
            "vm",
            "run",
            "--package-path",
            "./",
            "--module-id",
            "0x1::fibonacci",
            "--function-name",
            "test_fibonacci",
            "--args",
            "10u64",
        ],
        &pkg,
    );
    let witness = find_latest_file(&pkg.join("witnesses"), "test_fibonacci-", ".json");

    // Step 3 (Option 1): setup from the entry function, sized by Move.toml.
    // Write to a custom dir so it does not clash with the witness-based setup.
    run_zkmove(
        &[
            "vm",
            "setup",
            "--package-path",
            "./",
            "--circuit-name",
            "fibonacci",
            "--params-path",
            params,
            "--output-dir",
            "setup-from-entry",
        ],
        &pkg,
    );
    for f in ["params.bin", "pk.bin", "vk.bin", "metadata.json"] {
        assert!(
            pkg.join("setup-from-entry").join(f).is_file(),
            "setup (option 1) missing artifact {}",
            f
        );
    }

    // Step 3 (Option 2): setup from a witness, with public input indices.
    // Uses the default `setup/` dir consumed by prove/verify below.
    run_zkmove(
        &[
            "vm",
            "setup",
            "--package-path",
            "./",
            "--circuit-name",
            "fibonacci",
            "--params-path",
            params,
            "--witness",
            witness.to_str().unwrap(),
            "--pubs-indices",
            "0",
        ],
        &pkg,
    );
    for f in ["params.bin", "pk.bin", "vk.bin", "metadata.json"] {
        assert!(
            pkg.join("setup").join(f).is_file(),
            "setup (option 2) missing artifact {}",
            f
        );
    }
    // metadata.json should record the entry function so prove/verify don't
    // need --circuit-name.
    let metadata: serde_json::Value =
        serde_json::from_slice(&std::fs::read(pkg.join("setup").join("metadata.json")).unwrap())
            .expect("metadata.json is valid JSON");
    assert_eq!(metadata["module_id"], "0x1::fibonacci");
    assert_eq!(metadata["function_name"], "test_fibonacci");

    // Step 4: prove (runs the entry function internally, then proves).
    run_zkmove(
        &["vm", "prove", "--package-path", "./", "--args", "10u64"],
        &pkg,
    );
    let proof = find_latest_file(&pkg.join("proofs"), "test_fibonacci-", ".proof");
    let instance = proof.with_extension("instance");
    assert!(instance.is_file(), "missing instance file");
    assert!(proof.with_extension("vk").is_file(), "missing vk file");

    // Step 5: verify locally.
    run_zkmove(
        &[
            "vm",
            "verify",
            "--package-path",
            "./",
            "--pubs-path",
            instance.to_str().unwrap(),
            "--proof-path",
            proof.to_str().unwrap(),
        ],
        &pkg,
    );
}
