//! Печатает сценарий наблюдателя (macOS) — чтобы проверять его оболочкой:
//!
//!     cargo run -q --example dump_watcher > /tmp/watch.sh
//!     sh -n /tmp/watch.sh
//!
//! Наши тесты проверяют смысл, а синтаксис знает только сама оболочка.
fn main() {
    print!("{}", nexusproxy_core::tunnel_service::watcher_script(
        std::path::Path::new("/tmp/проверка")));
}
