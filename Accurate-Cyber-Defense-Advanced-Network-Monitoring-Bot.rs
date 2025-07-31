use std::{
    collections::HashSet,
    env, fs,
    io::{self, Write},
    process::{Command, Stdio},
    thread,
    time::Duration,
};
use serde::{Deserialize, Serialize};
use colored::*;

#[derive(Serialize, Deserialize, Debug)]
struct Config {
    telegram_token: Option<String>,
    telegram_chat_id: Option<String>,
    theme: String,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            telegram_token: None,
            telegram_chat_id: None,
            theme: "purple".to_string(),
        }
    }
}

struct Accurate {
    running: bool,
    monitored_ips: HashSet<String>,
    config: Config,
}

impl Accurate {
    fn new() -> Self {
        let mut pn = Accurate {
            running: true,
            monitored_ips: HashSet::new(),
            config: Config::default(),
        };
        pn.load_config();
        pn
    }

    fn load_config(&mut self) {
        let config_path = dirs::home_dir()
            .unwrap()
            .join(".Accurate_config");
        
        if config_path.exists() {
            match fs::read_to_string(&config_path) {
                Ok(contents) => {
                    match serde_json::from_str(&contents) {
                        Ok(config) => self.config = config,
                        Err(e) => self.print_error(&format!("Error parsing config: {}", e)),
                    }
                }
                Err(e) => self.print_error(&format!("Error reading config: {}", e)),
            }
        }
    }

    fn save_config(&self) {
        let config_path = dirs::home_dir()
            .unwrap()
            .join(".purplenet_config");
        
        match serde_json::to_string_pretty(&self.config) {
            Ok(contents) => {
                if let Err(e) = fs::write(&config_path, contents) {
                    self.print_error(&format!("Error saving config: {}", e));
                }
            }
            Err(e) => self.print_error(&format!("Error serializing config: {}", e)),
        }
    }

    fn print_banner(&self) {
        let banner = format!(
            r#"
{}{}

                                           
{}Accurate Cyber Defense Cyber Security Bot {}v14.0{}
{}Author: Ian Carter Kulani{}
{}License: For authorized security testing only{}
"#,
            "\x1b[95m",
            "\x1b[1m",
            "\x1b[35m",
            "\x1b[95m",
            "\x1b[0m",
            "\x1b[35m",
            "\x1b[0m",
            "\x1b[35m",
            "\x1b[0m",
        );
        println!("{}", banner);
    }

    fn print_error(&self, message: &str) {
        println!("{}", format!("[!] {}", message).purple());
    }

    fn print_success(&self, message: &str) {
        println!("{}", format!("[+] {}", message).cyan());
    }

    fn print_info(&self, message: &str) {
        println!("{}", format!("[*] {}", message).purple());
    }

    fn print_help(&self) {
        let help_menu = format!(
            r#"
{}PurpleNet Help Menu{}

{}General Commands:{}
    {}help{}               - Show this help menu
    {}clear{}              - Clear the screen
    {}exit{}               - Exit PurpleNet

{}Network Commands:{}
    {}ping <ip>{}          - Ping an IP address
    {}netscan <ip>{}       - Network scan of an IP range
    {}udptraceroute <ip>{} - UDP traceroute to an IP
    {}tcptraceroute <ip>{} - TCP traceroute to an IP

{}Monitoring Commands:{}
    {}start monitoring <ip>{} - Start monitoring an IP
    {}stop monitoring <ip>{}  - Stop monitoring an IP
    {}view{}                 - View monitored IPs

{}Configuration:{}
    {}config telegram_token <token>{}    - Set Telegram bot token
    {}config telegram_chat_id <id>{}     - Set Telegram chat ID
    {}test telegram{}                   - Test Telegram notification

{}Note:{} This tool is for authorized security testing only.
"#,
            "\x1b[95m".bold(),
            "\x1b[0m",
            "\x1b[95m",
            "\x1b[0m",
            "\x1b[96m",
            "\x1b[0m",
            "\x1b[96m",
            "\x1b[0m",
            "\x1b[96m",
            "\x1b[0m",
            "\x1b[95m",
            "\x1b[0m",
            "\x1b[96m",
            "\x1b[0m",
            "\x1b[96m",
            "\x1b[0m",
            "\x1b[96m",
            "\x1b[0m",
            "\x1b[96m",
            "\x1b[0m",
            "\x1b[95m",
            "\x1b[0m",
            "\x1b[96m",
            "\x1b[0m",
            "\x1b[96m",
            "\x1b[0m",
            "\x1b[96m",
            "\x1b[0m",
            "\x1b[95m",
            "\x1b[0m",
            "\x1b[96m",
            "\x1b[0m",
            "\x1b[96m",
            "\x1b[0m",
            "\x1b[96m",
            "\x1b[0m",
            "\x1b[95m",
            "\x1b[0m",
        );
        println!("{}", help_menu);
    }

    fn clear_screen(&self) {
        print!("{}[2J{}[H", 27 as char, 27 as char);
        self.print_banner();
    }

    fn ping_ip(&self, ip: &str) {
        self.print_info(&format!("Pinging {}...", ip));
        
        let output = if cfg!(target_os = "windows") {
            Command::new("ping")
                .args(&["-n", "4", ip])
                .output()
        } else {
            Command::new("ping")
                .args(&["-c", "4", ip])
                .output()
        };

        match output {
            Ok(output) => {
                if output.status.success() {
                    println!("{}", String::from_utf8_lossy(&output.stdout));
                } else {
                    self.print_error(&format!("Ping failed: {}", String::from_utf8_lossy(&output.stderr)));
                }
            }
            Err(e) => self.print_error(&format!("Failed to execute ping: {}", e)),
        }
    }

    fn netscan(&self, ip_range: &str) {
        self.print_info(&format!("Scanning network range {}...", ip_range));
        thread::sleep(Duration::from_secs(1));
        self.print_success("Conceptual network scan complete");
        self.print_info("This would show discovered hosts in a real implementation");
    }

    fn start_monitoring(&mut self, ip: &str) {
        if self.monitored_ips.contains(ip) {
            self.print_error(&format!("Already monitoring {}", ip));
            return;
        }
        
        self.monitored_ips.insert(ip.to_string());
        self.print_success(&format!("Started monitoring {}", ip));
        self.print_info("In a real tool, this would start packet capture and analysis");
    }

    fn stop_monitoring(&mut self, ip: &str) {
        if !self.monitored_ips.contains(ip) {
            self.print_error(&format!("Not currently monitoring {}", ip));
            return;
        }
        
        self.monitored_ips.remove(ip);
        self.print_success(&format!("Stopped monitoring {}", ip));
    }

    fn view_monitored(&self) {
        if self.monitored_ips.is_empty() {
            self.print_info("No IPs being monitored");
            return;
        }
        
        self.print_info("Monitored IPs:");
        for ip in &self.monitored_ips {
            println!(" - {}", ip);
        }
    }

    fn udp_traceroute(&self, ip: &str) {
        self.print_info(&format!("Performing UDP traceroute to {}...", ip));
        thread::sleep(Duration::from_secs(1));
        self.print_success("Conceptual UDP traceroute complete");
    }

    fn tcp_traceroute(&self, ip: &str) {
        self.print_info(&format!("Performing TCP traceroute to {}...", ip));
        thread::sleep(Duration::from_secs(1));
        self.print_success("Conceptual TCP traceroute complete");
    }

    fn test_telegram(&self) {
        if self.config.telegram_token.is_none() || self.config.telegram_chat_id.is_none() {
            self.print_error("Telegram token or chat ID not configured");
            return;
        }
        
        self.print_info("Sending test Telegram notification...");
        thread::sleep(Duration::from_secs(1));
        self.print_success("Conceptual Telegram test complete");
    }

    fn config_telegram(&mut self, key: &str, value: &str) {
        match key {
            "telegram_token" => {
                self.config.telegram_token = Some(value.to_string());
                self.print_success("Telegram token configured");
            }
            "telegram_chat_id" => {
                self.config.telegram_chat_id = Some(value.to_string());
                self.print_success("Telegram chat ID configured");
            }
            _ => {
                self.print_error("Invalid configuration key");
                return;
            }
        }
        
        self.save_config();
    }

    fn generate_traffic(&self, ip: &str, traffic_type: &str, duration: &str) {
        self.print_info(&format!(
            "Generating {} traffic to {} for {} seconds...",
            traffic_type, ip, duration
        ));
        thread::sleep(Duration::from_secs(1));
        self.print_success("Conceptual traffic generation complete");
    }

    fn spoof_ip(&self, ip: &str) {
        self.print_info(&format!("Demonstrating IP spoofing concept with {}", ip));
        self.print_info("In a real implementation, this would modify packet headers");
        thread::sleep(Duration::from_secs(1));
        self.print_success("Conceptual IP spoofing demonstration complete");
    }

    fn spoof_mac(&self, mac: &str) {
        self.print_info(&format!("Demonstrating MAC spoofing concept with {}", mac));
        self.print_info("In a real implementation, this would modify network interface MAC");
        thread::sleep(Duration::from_secs(1));
        self.print_success("Conceptual MAC spoofing demonstration complete");
    }

    fn send_phishing_page(&self) {
        self.print_info("Demonstrating phishing page concept");
        self.print_info("In a real implementation, this would serve a fake login page");
        thread::sleep(Duration::from_secs(1));
        self.print_success("Conceptual phishing demonstration complete");
    }

    fn process_command(&mut self, command: &str) {
        let parts: Vec<&str> = command.trim().split_whitespace().collect();
        if parts.is_empty() {
            return;
        }

        let cmd = parts[0].to_lowercase();

        match cmd.as_str() {
            "help" => self.print_help(),
            "clear" => self.clear_screen(),
            "exit" => self.running = false,
            "ping" if parts.len() > 1 => self.ping_ip(parts[1]),
            "netscan" if parts.len() > 1 => self.netscan(parts[1]),
            "udptraceroute" if parts.len() > 1 => self.udp_traceroute(parts[1]),
            "tcptraceroute" if parts.len() > 1 => self.tcp_traceroute(parts[1]),
            "start" if parts.len() > 2 && parts[1].to_lowercase() == "monitoring" => {
                self.start_monitoring(parts[2])
            }
            "stop" if parts.len() > 2 && parts[1].to_lowercase() == "monitoring" => {
                self.stop_monitoring(parts[2])
            }
            "view" => self.view_monitored(),
            "test" if parts.len() > 1 && parts[1].to_lowercase() == "telegram" => self.test_telegram(),
            "config" if parts.len() > 2 => self.config_telegram(parts[1], parts[2]),
            "generate" if parts.len() > 3 && parts[1].to_lowercase() == "traffic" => {
                self.generate_traffic(parts[2], parts[3], parts[4])
            }
            "spoof" if parts.len() > 1 => {
                if parts[1].contains(':') || parts[1].contains('-') {
                    self.spoof_mac(parts[1])
                } else {
                    self.spoof_ip(parts[1])
                }
            }
            "phish" => self.send_phishing_page(),
            _ => self.print_error("Unknown command or missing parameters. Type 'help' for available commands."),
        }
    }

    fn run(&mut self) {
        self.clear_screen();
        
        while self.running {
            print!("{}purplenet>{} ", "\x1b[95m", "\x1b[0m");
            io::stdout().flush().unwrap();
            
            let mut command = String::new();
            match io::stdin().read_line(&mut command) {
                Ok(_) => {
                    self.process_command(&command);
                }
                Err(e) => {
                    self.print_error(&format!("Error reading input: {}", e));
                    continue;
                }
            }
        }
        
        self.print_info("Exiting Accurate...");
    }
}

fn main() {
    let mut tool = Accurate::new();
    tool.run();
}