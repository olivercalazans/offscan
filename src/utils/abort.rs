pub(crate) fn abort(error: impl Into<String>) -> ! {
    eprintln!("[ ERROR ] {}", error.into());
    std::process::exit(1);
}