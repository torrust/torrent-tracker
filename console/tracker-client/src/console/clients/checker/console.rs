use super::printer::{Printer, CLEAR_SCREEN};

pub struct Console {}

impl Default for Console {
    fn default() -> Self {
        Self::new()
    }
}

impl Console {
    #[must_use]
    pub fn new() -> Self {
        Self {}
    }
}

impl Printer for Console {
    fn clear(&self) {
        self.print(CLEAR_SCREEN);
    }

    fn print(&self, output: &str) {
        print!("{}", &output);
    }

    fn eprint(&self, output: &str) {
        eprint!("{}", &output);
    }

    fn println(&self, output: &str) {
        println!("{}", &output);
    }

    fn eprintln(&self, output: &str) {
        eprintln!("{}", &output);
    }
}
