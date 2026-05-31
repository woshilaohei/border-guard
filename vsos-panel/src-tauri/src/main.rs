// VSOS Guard v0.6.0 - Tauri Backend
// 读取Python后端写入的status.json，暴露给前端

use std::fs;
use std::path::PathBuf;
use tauri::command;

/// 获取状态文件路径（跨平台）
fn get_status_file() -> PathBuf {
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    home.join(".vsos_guard").join("status.json")
}

/// 读取status.json内容
#[command]
fn read_status() -> Result<String, String> {
    let path = get_status_file();
    if !path.exists() {
        return Err("status.json not found - demo mode".into());
    }
    fs::read_to_string(&path).map_err(|e| format!("Failed to read status: {}", e))
}

/// 获取状态文件路径信息（给前端调试用）
#[command]
fn get_status_path() -> String {
    get_status_file().to_string_lossy().to_string()
}

/// 写入安全等级配置
#[command]
fn set_security_level(level: String) -> Result<String, String> {
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    let config_dir = home.join(".vsos_guard");
    fs::create_dir_all(&config_dir).map_err(|e| format!("Failed to create config dir: {}", e))?;
    let config_path = config_dir.join("security_level.json");
    let config = serde_json::json!({
        "level": level,
        "updated_at": chrono::Utc::now().to_rfc3339(),
    });
    let content = serde_json::to_string_pretty(&config).map_err(|e| format!("JSON error: {}", e))?;
    fs::write(&config_path, content).map_err(|e| format!("Failed to write config: {}", e))?;
    Ok(format!("Security level set to {}", level))
}

cfg_if::cfg_if! {
    if #[cfg(not(target_os = "macos"))] {
        fn main() {
            tauri::Builder::default()
                .plugin(tauri_plugin_shell::init())
                .invoke_handler(tauri::generate_handler![read_status, get_status_path, set_security_level])
                .run(tauri::generate_context!())
                .expect("error while running tauri application");
        }
    }
}
