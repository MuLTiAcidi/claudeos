use portable_pty::{native_pty_system, CommandBuilder, PtySize};
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use tauri::{Emitter, State};

struct TerminalState {
    writer: Arc<Mutex<Option<Box<dyn Write + Send>>>>,
    alive: Arc<Mutex<bool>>,
}

#[tauri::command]
fn spawn_terminal(state: State<'_, TerminalState>, app: tauri::AppHandle) -> Result<String, String> {
    let pty_system = native_pty_system();

    let pty_pair = pty_system
        .openpty(PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        })
        .map_err(|e| e.to_string())?;

    let shell = std::env::var("SHELL").unwrap_or_else(|_| {
        if cfg!(target_os = "windows") {
            "powershell.exe".to_string()
        } else {
            "/bin/zsh".to_string()
        }
    });

    let mut cmd = CommandBuilder::new(&shell);
    cmd.env("TERM", "xterm-256color");

    // Find ClaudeOS directory — search common locations
    let home = std::env::var("HOME").unwrap_or_default();
    let possible_paths = vec![
        format!("{}/Desktop/Claude/claudeos", home),
        format!("{}/claudeos", home),
        format!("{}/ClaudeOS", home),
        format!("{}/Desktop/claudeos", home),
    ];

    let mut claudeos_dir = home.clone();
    for path in &possible_paths {
        let claude_md = format!("{}/CLAUDE.md", path);
        if std::path::Path::new(&claude_md).exists() {
            claudeos_dir = path.clone();
            break;
        }
    }
    cmd.cwd(&claudeos_dir);

    let mut child = pty_pair.slave.spawn_command(cmd).map_err(|e| e.to_string())?;
    drop(pty_pair.slave);

    let writer = pty_pair.master.take_writer().map_err(|e| e.to_string())?;
    {
        let mut w = state.writer.lock().unwrap();
        *w = Some(writer);
    }
    {
        let mut a = state.alive.lock().unwrap();
        *a = true;
    }

    let mut reader = pty_pair.master.try_clone_reader().map_err(|e| e.to_string())?;
    let alive_clone = state.alive.clone();

    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    let data = String::from_utf8_lossy(&buf[..n]).to_string();
                    let _ = app.emit("terminal-output", &data);
                }
                Err(_) => break,
            }
        }
        let mut a = alive_clone.lock().unwrap();
        *a = false;
    });

    std::thread::spawn(move || {
        let _ = child.wait();
    });

    Ok("Terminal spawned".to_string())
}

#[tauri::command]
fn write_terminal(state: State<'_, TerminalState>, data: String) -> Result<(), String> {
    let mut w = state.writer.lock().unwrap();
    if let Some(ref mut writer) = *w {
        writer.write_all(data.as_bytes()).map_err(|e| e.to_string())?;
        writer.flush().map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let terminal_state = TerminalState {
        writer: Arc::new(Mutex::new(None)),
        alive: Arc::new(Mutex::new(false)),
    };

    tauri::Builder::default()
        .manage(terminal_state)
        .invoke_handler(tauri::generate_handler![
            spawn_terminal,
            write_terminal,
        ])
        .setup(|app| {
            if cfg!(debug_assertions) {
                app.handle().plugin(
                    tauri_plugin_log::Builder::default()
                        .level(log::LevelFilter::Info)
                        .build(),
                )?;
            }
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
