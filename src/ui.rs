use prettytable::Table;
use std::io::{stdout, Write};
use std::sync::mpsc::Receiver;
use std::{thread, time};
extern crate termion;
use ui::termion::screen::*;

pub struct UIData {
    pub container_name: String,
    pub memory: f64,
}

pub fn display(receiver: Receiver<Vec<UIData>>) {
    let mut screen = AlternateScreen::from(stdout());

    loop {
        if let Ok(msg) = receiver.recv() {
            write!(
                screen,
                "{} {}",
                termion::clear::All,
                termion::cursor::Goto(1, 1)
            );
            screen.flush().unwrap();
            let mut table = Table::new();
            table.add_row(row!["container name", "memory"]);
            for i in 0..msg.len() {
                table.add_row(row![
                    msg[i].container_name,
                    msg[i].memory.to_string() + " MB"
                ]);
            }
            write!(screen, "{}", table);
            screen.flush().unwrap();
        }
        thread::sleep(time::Duration::from_millis(10));
    }
}
