extern crate cc;

fn main() {
    cc::Build::new()
        .warnings(false)
        .extra_warnings(false)
        .static_flag(true)
        .file("c/tweetnacl.c")
        .compile("tweetnacl");
}
