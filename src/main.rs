use clap;
use clap::Parser;
use home::home_dir;
use log::{error, info, trace, Level, Metadata, Record};
use log::{SetLoggerError, STATIC_MAX_LEVEL};
use regex::Regex;
use rustyline::error::ReadlineError;
use rustyline::Editor;
use serde_derive::{Deserialize, Serialize};
use std::fs;
use std::io::{Read, Write};
use std::path::Path;
use std::{process::Command, thread, time::Duration};
use toml;
use xrandr::XHandle;

struct SimpleLogger;

impl log::Log for SimpleLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= Level::Info
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            println!(":: {} - {}", record.level(), record.args());
        }
    }
    fn flush(&self) {}
}

static LOGGER: SimpleLogger = SimpleLogger;

pub fn init_log() -> Result<(), SetLoggerError> {
    log::set_logger(&LOGGER).map(|()| log::set_max_level(STATIC_MAX_LEVEL))
}

#[derive(Debug, Clone)]
struct Device {
    id: u64,
    device: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Config {
    device: String,
    monitor: String,
}

fn banner() {
    println!(
        r#"
    ___  ___                    ___               
    / _ \/ _ \_______ __    __  / _ | _______ ___ _
   / , _/ // / __/ _ `/ |/|/ / / __ |/ __/ -_) _ `/
  /_/|_/____/_/  \_,_/|__,__/ /_/ |_/_/  \__/\_,_/ 

        "#
    )
}

fn find_devices(filter: Option<String>) -> Vec<Device> {
    let mut result: Vec<Device> = vec![];

    let output = Command::new("xinput")
        .output()
        .expect("failed to execute process xinput");
    trace!("status: {}", output.status);
    trace!("stdout: {}", String::from_utf8_lossy(&output.stdout));
    trace!("stderr: {}", String::from_utf8_lossy(&output.stderr));

    assert!(output.status.success());

    let out = String::from_utf8_lossy(&output.stdout);

    let pen_regepr: String = filter.unwrap_or("PEN|STYLUS".to_string());
    let re = Regex::new(format!(r"^.*{}.*$", pen_regepr).as_str()).unwrap();
    // ^[\W]+?\s([\w\s]+)[\s]+ID=*(\d+).*?$
    let reid = Regex::new(r"^.*?\s(?P<device>\w[\w\W\s]+?)[\s]+ID=*(?P<id>\d+).*?$").unwrap();

    for line in out.split("\n") {
        let line_up = &line.to_uppercase();
        if re.is_match(line_up) {
            trace!("{}", line_up);
            let caps = reid
                .captures(line_up)
                .expect("Expected one of DEVICE ID=00 in xinput");
            trace!("device {} id {}", &caps["device"], &caps["id"]);

            let a_device = Device {
                id: caps["id"].parse::<u64>().unwrap(),
                device: caps["device"].to_string(),
            };

            trace!("{:?}", &a_device);
            result.push(a_device);
        }
    }
    result
}

// Config{device: "pen|stylus".to_string(), display: "HDMI-0".to_string()}
fn get_config() -> Config {
    let home_dir = home_dir().unwrap();
    let config_path = home_dir.join(".config/draw_area/");
    let config_filename = "config.toml";

    trace!("config dir: {}", config_path.display());
    fs::create_dir_all(&config_path).expect("Unable to create the config directory");

    let config_full_path = format!("{}/{}", config_path.display(), config_filename);

    if !Path::new(&config_full_path).exists() {
        info!("Config file {} not found", &config_full_path);
        match fs::File::create(&config_full_path) {
            Ok(mut file) => {
                file.write(toml::to_string(&Config::default()).unwrap().as_bytes())
                    .unwrap();
            }
            Err(_) => {}
        }
    }

    let mut file_str = String::new();
    match fs::File::open(&config_full_path) {
        Ok(mut ok) => {
            ok.read_to_string(&mut file_str).unwrap();
        }
        Err(_) => {
            file_str = "".to_string();
        }
    }

    let config: Config = toml::from_str(&file_str).expect(
        format!(
            "Corrupted config file at {}, either fix it or delete it",
            config_full_path
        )
        .as_str(),
    );

    config
}

// Config{device: "pen|stylus".to_string(), display: "HDMI-0".to_string()}
fn save_config(config: &Config) {
    let home_dir = home_dir().unwrap();
    let config_path = home_dir.join(".config/draw_area/");
    let config_filename = "config.toml";
    let config_string: String = toml::to_string_pretty(&config).unwrap();

    trace!("config dir: {}", config_path.display());
    fs::create_dir_all(&config_path).expect("Unable to create the config directory");

    let config_full_path = format!("{}/{}", config_path.display(), config_filename);

    match fs::File::create(&config_full_path) {
        Ok(mut file) => {
            file.write(config_string.as_bytes()).unwrap();
        }
        Err(_) => {}
    }
}

fn select_device() -> Result<Device, ReadlineError> {
    let mut rl = Editor::<()>::new().unwrap();
    loop {
        println!("");
        println!("Select the table pen: ");
        println!("");
        let devices = find_devices(None);
        let mut counter = 1;
        for d in &devices {
            println!("- {} {}", counter, d.device);
            counter += 1;
        }
        println!("");
        let readline = rl.readline(format!("device [1-{}]: ", counter - 1).as_str());
        match readline {
            Ok(line) => {
                let selected_id = line.parse::<usize>();
                if selected_id.is_ok() {
                    let selected_id = selected_id.unwrap();
                    println!("");
                    if selected_id > 0 && selected_id <= devices.len() {
                        return Ok(devices[selected_id - 1].clone());
                    }
                } else {
                    println!("");
                    println!("Select the device with a number[1-{}]!", counter - 1);
                    println!("");
                }
            }
            Err(ReadlineError::Interrupted) => {
                println!("CTRL-C");
                return Err(ReadlineError::Interrupted);
            }
            Err(err) => {
                println!("Error: {:?}", err);
                break;
            }
        }
    }
    Ok(Device {
        id: 0,
        device: "PEN".to_string(),
    })
}

fn select_monitor() -> Result<String, ReadlineError> {
    let monitors = XHandle::open()
        .expect("Unable to load xrandr lib")
        .monitors()
        .unwrap();

    let mut rl = Editor::<()>::new().unwrap();
    loop {
        println!("");
        println!("Select the output monitor: ");
        println!("");
        let monitors = XHandle::open()
            .expect("Unable to load xrandr lib")
            .monitors()
            .unwrap();

        let mut counter = 1;
        for m in &monitors {
            println!("- {} {}", counter, m.name);
            counter += 1;
        }
        println!("");
        let readline = rl.readline(format!("monitor [1-{}]: ", counter - 1).as_str());
        match readline {
            Ok(line) => {
                let selected_id = line.parse::<usize>();
                if selected_id.is_ok() {
                    let selected_id = selected_id.unwrap();
                    println!("");
                    if selected_id > 0 && selected_id <= monitors.len() {
                        return Ok(monitors[selected_id - 1].name.to_string());
                    }
                } else {
                    println!("");
                    println!("Select the device with a number[1-{}]!", counter - 1);
                    println!("");
                }
            }
            Err(ReadlineError::Interrupted) => {
                println!("CTRL-C");
                return Err(ReadlineError::Interrupted);
            }
            Err(err) => {
                println!("Error: {:?}", err);
                break;
            }
        }
    }
    Ok(monitors.get(0).unwrap().name.to_string())
}

fn setup() -> Result<Config, ReadlineError> {
    let selected_device = select_device()?;
    let selected_monitor = select_monitor()?;

    Ok(Config {
        device: selected_device.device.to_owned(),
        monitor: selected_monitor,
    })
}

/// Map the drawing tablet area to a display
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Watch for xrandr changes [WARNING lags]
    #[arg(long)]
    watch_display: bool,

    /// Watch for xinput changes
    #[arg(long)]
    watch_xinput: bool,

    /// Pooling time in seconds
    #[arg(short, long, value_name = "seconds", default_value_t = 10)]
    pool: u64,

    /// Remove the welcome banner
    #[arg(short, long)]
    no_banner: bool,
}

fn main() {
    match init_log() {
        Ok(_) => (),
        Err(_) => println!("Error"),
    }

    let args = Args::parse();

    if !args.no_banner {
        banner();
    }

    let mut config = get_config();

    if config.device == "" || config.monitor == "" {
        config = setup().unwrap();
        save_config(&config);
    }

    let mut old_devicegfmt = String::from("");
    loop {
        let mut monitors = vec![];
        let mut devicefmt = String::from("empty"); // run at least 1 loop

        if args.watch_display {
            monitors = XHandle::open()
                .expect("Unable to load xrandr lib")
                .monitors()
                .unwrap();
            devicefmt = format!("{:#?}", monitors);
        } else if args.watch_xinput {
            let devices = find_devices(Some(config.device.to_owned()));
            devicefmt = format!("{:#?}", devices);
        }

        if devicefmt != old_devicegfmt {
            old_devicegfmt = devicefmt;
            if args.watch_display {
                trace!("{:#?}", monitors);
                info!("Monitor updated!");
                info!("");
            } else if args.watch_xinput {
                info!("xinput updated!");
                info!("");
            }
            info!("Aviable monitors:");
            info!("");
            for m in monitors {
                info!(" - {}", m.name);
            }
            info!("");
            //println!("{:?}", config);

            let devices = find_devices(Some(config.device.to_owned()));

            for d in devices {
                trace!("{:?}", d);
                let monitor = config.monitor.as_str();
                let output = Command::new("xinput")
                    .args(["map-to-output", d.id.to_string().as_str(), monitor])
                    .output()
                    .expect("failed to execute process xinput");

                trace!("status: {}", output.status);
                trace!("stdout: {}", String::from_utf8_lossy(&output.stdout));
                if !output.status.success() {
                    error!("stderr: {}", String::from_utf8_lossy(&output.stderr));
                    //assert!(output.status.success());
                } else {
                    info!("");
                    println!("set {} to {} successful", d.device, monitor);
                    info!("");
                }
            }
        }
        if args.watch_display || args.watch_xinput {
            thread::sleep(Duration::from_millis(args.pool * 1000));
        } else {
            break;
        }
    }
}
