fn main() {
    // Pin the widget style. The app draws its own controls, but std-widgets'
    // ListView still supplies the scrollbars, and leaving the style to the
    // platform default would give macOS cupertino scrollbars and Linux fluent
    // ones inside an otherwise identical window.
    let config = slint_build::CompilerConfiguration::new().with_style("fluent".into());
    // A test-only harness for tests/accessibility.rs. Compiled unconditionally
    // because a build script cannot tell that it is building for `cargo test`;
    // it is one small component and nothing in the binary refers to it.
    //
    // Compiled *before* the app, because each call overwrites the variable
    // that slint::include_modules!() reads: the last one compiled is the one
    // main.rs gets. The test include!s its own file by name.
    // with_debug_info is what makes the ElementHandle API able to see the
    // element tree. Set on the probe alone so the shipped binary does not
    // carry it.
    slint_build::compile_with_config(
        "ui/testing/field-probe.slint",
        config.clone().with_debug_info(true),
    )
    .expect("compiling ui/testing/field-probe.slint");

    slint_build::compile_with_config("ui/app-window.slint", config)
        .expect("compiling ui/app-window.slint");
}
