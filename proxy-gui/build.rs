fn main() {
    #[cfg(target_os = "windows")]
    embed_resource::compile("assets/windows.rc", embed_resource::NONE)
        .manifest_optional()
        .expect("failed to embed Rama Proxy icons");
}
