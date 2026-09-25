//! Печатает сценарий установки службы — чтобы проверять его настоящим
//! разборщиком оболочки, а не на глаз.
fn main() {
    let dir = std::path::PathBuf::from(
        std::env::args().nth(1).unwrap_or_else(|| r"C:\Users\и.коробков\AppData\Roaming\org.hipogas.nexusproxy\tunnel".into()));
    print!("{}", nexusproxy_core::tunnel_service::install_script(&dir));
}
