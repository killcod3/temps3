use std::process::Command;

#[test]
fn test_cli_help() {
    let output = Command::new("cargo")
        .args(["run", "--", "--help"])
        .output()
        .expect("Failed to execute command");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("Invalid UTF-8");
    assert!(stdout.contains("A CLI application for temporary file storage"));
    assert!(stdout.contains("Commands:"));
    assert!(stdout.contains("init"));
    assert!(stdout.contains("upload"));
    assert!(stdout.contains("list"));
    assert!(stdout.contains("config"));
}

#[test]
fn test_upload_command_help() {
    let output = Command::new("cargo")
        .args(["run", "--", "upload", "--help"])
        .output()
        .expect("Failed to execute command");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("Invalid UTF-8");
    assert!(stdout.contains("Upload a file to S3 with TTL"));
    assert!(stdout.contains("--ttl"));
    assert!(stdout.contains("--verbose"));
}

#[test]
fn test_version() {
    let output = Command::new("cargo")
        .args(["run", "--", "--version"])
        .output()
        .expect("Failed to execute command");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("Invalid UTF-8");
    assert!(stdout.contains("temps3"));
    assert!(stdout.contains("0.1.0"));
}
