pub const CLEAR_SCREEN: &str = "\x1B[2J\x1B[1;1H";

pub trait Printer {
    fn clear(&self);
    fn print(&self, output: &str);
    fn eprint(&self, output: &str);
    fn println(&self, output: &str);
    fn eprintln(&self, output: &str);
}
