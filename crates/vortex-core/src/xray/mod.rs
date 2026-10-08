pub mod backend;
pub mod config;
pub mod install;

pub use backend::XrayBackend;
pub use config::{generate_xray_config, generate_xray_outbound, validate_xray_config_file};
pub use install::{
    active_xray_version, current_symlink_path, fetch_latest_release_info, get_binary_version,
    install_xray, managed_xray_binary, refresh_geo_databases, resolve_installed_version,
    resolve_xray_binary, rollback_xray, run_xray_doctor, which_in_path, xray_data_dir,
    DoctorReport, XrayReleaseInfo,
};
