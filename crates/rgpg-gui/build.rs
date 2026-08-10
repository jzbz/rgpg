fn main() {
    // Pin the widget style. The app draws its own controls, but std-widgets'
    // ListView still supplies the scrollbars, and leaving the style to the
    // platform default would give macOS cupertino scrollbars and Linux fluent
    // ones inside an otherwise identical window.
    let config = slint_build::CompilerConfiguration::new().with_style("fluent".into());
    slint_build::compile_with_config("ui/app-window.slint", config)
        .expect("compiling ui/app-window.slint");
}
