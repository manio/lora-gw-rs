use atomic_enum::atomic_enum;
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    XChaCha20Poly1305, XNonce,
};
use rppal::gpio::Gpio;
use rppal::gpio::Trigger;
use simplelog::*;
use std::env;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::task;
use tokio::time::timeout;
use tokio_serial::SerialPortBuilderExt;
use tokio_serial::SerialStream;

// module name for logging engine
const NAME: &str = "<i><bright-black> main: </>";

// Just a generic Result type to ease error handling for us. Errors in multithreaded
// async contexts needs some extra restrictions
type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

const ACTION_PIN: u8 = 4; //BCM pin #
const ACTION_CMD: &str = "lora-action.sh";

// sample key for client and server - generate a new one for your application !!!
const KEY: &[u8; 32] = &[
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
];
const NONCE_SIZE: usize = 24;
const TAG_SIZE: usize = 16;

const CMD_NONCE_REQ: [u8; 1] = [0x88];
const CMD_OPENGATE_REQ: [u8; 1] = [0x89];
const CMD_OPENGATE_ACK: [u8; 1] = [0x02];

#[atomic_enum]
#[derive(PartialEq)]
enum State {
    Idle,
    ButtonPressed,
    Processing,
    Terminating,
}

#[derive(PartialEq)]
enum RunMode {
    Help,
    Client,
    Server,
}

pub struct Lora {
    pub display_name: String,
    device: SerialStream,
    nonce: Option<XNonce>,
    run_mode: RunMode,
}

impl Lora {
    pub async fn send_recv(
        &mut self,
        data: Option<&[u8]>,
        reply_size: Option<usize>,
        silent_timeout: bool,
    ) -> Result<Option<Vec<u8>>> {
        let mut out: Option<Vec<u8>> = None;

        if let Some(data) = data {
            info!("{} <b><red>>>></> {:02X?}", self.display_name, data);
            if let Err(e) = self.device.write_all(&data).await {
                error!("{} write error: {:?}", self.display_name, e);
                return Ok(out);
            }
        }
        let now = Instant::now();

        if let Some(reply_size) = reply_size {
            let mut buffer = vec![0u8; reply_size];
            let retval = self.device.read_exact(&mut buffer);
            match timeout(Duration::from_secs_f32(10.0), retval).await {
                Ok(res) => match res {
                    Ok(_) => {
                        let elapsed = now.elapsed();
                        info!(
                            "{} <b><green><<<</> {:02X?} (⏱️ {} ms)",
                            self.display_name,
                            &buffer,
                            (elapsed.as_secs() * 1_000)
                                + (elapsed.subsec_nanos() / 1_000_000) as u64,
                        );
                        out = Some(buffer)
                    }
                    Err(e) => {
                        error!("{} read error: {}", self.display_name, e);
                    }
                },
                Err(e) => {
                    if !silent_timeout {
                        error!("{} response timeout: {}", self.display_name, e);
                    }
                }
            }
        }

        Ok(out)
    }

    async fn get_nonce(&mut self) {
        // request a new nonce from server
        info!("{} sending nonce request...", self.display_name);
        if let Ok(Some(b)) = self
            .send_recv(Some(&CMD_NONCE_REQ), Some(NONCE_SIZE), false)
            .await
        {
            // loading from slice into new nonce
            self.nonce = Some(*XNonce::from_slice(&b));
        }
    }

    async fn worker(&mut self, state: Arc<AtomicState>) -> Result<()> {
        info!("{} starting task", self.display_name);
        let mut try_nonce_request = true;

        let cipher = XChaCha20Poly1305::new(KEY.into());

        loop {
            if state.load(Ordering::SeqCst) == State::Terminating {
                debug!("{} got terminate signal from main", self.display_name);
                break;
            }

            if self.run_mode == RunMode::Server {
                debug!("waiting for command...");
                if let Ok(Some(b)) = self.send_recv(None, Some(1), true).await {
                    match b.try_into().unwrap() {
                        CMD_NONCE_REQ => {
                            info!("{} <b><green>CMD_NONCE_REQ</>", self.display_name);

                            // generating new nonce 192-bits; unique per message
                            self.nonce = Some(XChaCha20Poly1305::generate_nonce(&mut OsRng));
                            // sending this nonce to client
                            let _ = self
                                .send_recv(Some(&self.nonce.unwrap()), None, false)
                                .await?;
                        }
                        CMD_OPENGATE_REQ => {
                            info!("{} <b><green>CMD_OPENGATE_REQ</>", self.display_name);
                            match self.nonce {
                                Some(nonce) => {
                                    let buffer = self
                                        .send_recv(
                                            None,
                                            Some(TAG_SIZE + CMD_OPENGATE_REQ.len()),
                                            false,
                                        )
                                        .await?;
                                    if let Some(b) = buffer {
                                        let plaintext = cipher.decrypt(&nonce, b.as_ref());
                                        if let Ok(text) = plaintext {
                                            if text == CMD_OPENGATE_REQ {
                                                info!(
                                                    "{} <blue>request OK, calling a command...</>",
                                                    self.display_name
                                                );
                                                let output = std::process::Command::new(ACTION_CMD)
                                                    .output()
                                                    .expect("Error calling script");
                                                debug!(
                                                    "script call result:\nstdout: {:?}\nstderr: {:?}",
                                                    String::from_utf8(output.stdout),
                                                    String::from_utf8(output.stderr)
                                                );

                                                // encrypting message
                                                let ciphertext = cipher
                                                    .encrypt(&nonce, CMD_OPENGATE_ACK.as_ref())
                                                    .unwrap();
                                                // sending response to client
                                                let _ = self
                                                    .send_recv(Some(&ciphertext), None, false)
                                                    .await;
                                            }
                                        } else {
                                            error!("{} decoding error", self.display_name);
                                        }
                                    }

                                    // nonce invalidation
                                    self.nonce = None;
                                }
                                None => {
                                    error!(
                                        "{} FATAL: client sent request but we don't have a nonce!",
                                        self.display_name
                                    );
                                }
                            }
                        }
                        _ => {
                            error!("{} unknown LoRa CMD received", self.display_name);
                        }
                    }
                }
            } else {
                if try_nonce_request {
                    self.get_nonce().await;
                    try_nonce_request = false;
                }
                if state.load(Ordering::SeqCst) == State::Processing {
                    // clearing processing flag
                    state.store(State::Idle, Ordering::SeqCst);
                } else if state.load(Ordering::SeqCst) == State::ButtonPressed {
                    let now = Instant::now();
                    state.store(State::Processing, Ordering::SeqCst);

                    // request a new nonce if it is None
                    if let None = self.nonce {
                        self.get_nonce().await;
                    }

                    if let Some(nonce) = self.nonce {
                        // encrypting message
                        let mut ciphertext: Vec<u8> = CMD_OPENGATE_REQ.to_vec();
                        ciphertext.append(
                            &mut cipher.encrypt(&nonce, CMD_OPENGATE_REQ.as_ref()).unwrap(),
                        );
                        // sending request to server
                        if let Ok(Some(b)) = self
                            .send_recv(
                                Some(&ciphertext),
                                Some(TAG_SIZE + CMD_OPENGATE_ACK.len()),
                                false,
                            )
                            .await
                        {
                            // decrypting message
                            let plaintext = cipher.decrypt(&nonce, b.as_ref());
                            if let Ok(text) = plaintext {
                                if text == CMD_OPENGATE_ACK {
                                    info!(
                                        "{} <blue>server has ACK-ed calling an action!</>",
                                        self.display_name
                                    );
                                }
                                let elapsed = now.elapsed();
                                info!(
                                    "{} total time: ⏱️ {} ms",
                                    self.display_name,
                                    (elapsed.as_secs() * 1_000)
                                        + (elapsed.subsec_nanos() / 1_000_000) as u64
                                );
                            } else {
                                error!("{} decoding error", self.display_name);
                            }
                        }
                        // nonce invalidation
                        self.nonce = None;
                    } else {
                        error!("{} can't obtain a nonce!", self.display_name);
                    }

                    try_nonce_request = true;
                }
            }

            tokio::time::sleep(Duration::from_millis(30)).await;
        }

        info!("{} task stopped", self.display_name);
        Ok(())
    }
}

fn logging_init(debug: bool) {
    let conf = ConfigBuilder::new()
        .set_time_format("%F, %H:%M:%S%.3f".to_string())
        .set_write_log_enable_colors(true)
        .build();

    let mut loggers = vec![];

    let console_logger: Box<dyn SharedLogger> = TermLogger::new(
        if debug {
            LevelFilter::Debug
        } else {
            LevelFilter::Info
        },
        conf.clone(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    );
    loggers.push(console_logger);

    CombinedLogger::init(loggers).expect("Cannot initialize logging subsystem");
}

#[tokio::main]
async fn main() -> Result<()> {
    logging_init(false);
    info!("<b><blue>lora-gw-rs</> started");

    let argument = env::args().nth(1);
    let run_mode = if let Some(arg) = argument {
        match &arg[..] {
            "client" => RunMode::Client,
            "server" => RunMode::Server,
            _ => RunMode::Help,
        }
    } else {
        RunMode::Help
    };

    if run_mode == RunMode::Help {
        println! {"No arguments given, possible choices: [ client | server ]\n"};
        return Ok(());
    };

    // main program state
    let state = Arc::new(AtomicState::new(State::Idle));

    // Ctrl-C / SIGTERM support
    let s = state.clone();
    ctrlc::set_handler(move || {
        s.store(State::Terminating, Ordering::SeqCst);
    })
    .expect("Error setting Ctrl-C handler");

    // button handling on client
    // the following variables has to be here, otherwise they will be dropped
    // because going out of scope:
    // https://github.com/golemparts/rppal/issues/41#issuecomment-2343238388
    let g;
    let mut pin;
    if run_mode == RunMode::Client {
        let s = state.clone();

        // Retrieve the GPIO pin and configure it as an output.
        g = Gpio::new().expect("GPIO setup problem");
        pin = g
            .get(ACTION_PIN)
            .expect("GPIO button pin get() problem")
            .into_input_pullup();
        let _ = pin.set_async_interrupt(
            Trigger::FallingEdge,
            Some(Duration::from_millis(5)),
            move |_| {
                if s.load(Ordering::SeqCst) == State::Idle {
                    info!("{} button press!", NAME);
                    s.store(State::ButtonPressed, Ordering::SeqCst);
                } else {
                    info!("{} button press ignored!", NAME);
                }
            },
        );
    }

    // LoRa serial device handling in task
    let s = state.clone();
    let device_path = {
        if run_mode == RunMode::Client {
            "/dev/ttyAMA0"
        } else {
            "/dev/ttyUSB0"
        }
    };
    let mut device = tokio_serial::new(device_path, 9600).open_native_async()?;

    #[cfg(unix)]
    device
        .set_exclusive(false)
        .expect("Unable to set serial port exclusive to false");

    info!("{} serial device {} opened", NAME, device_path);

    let mut lora = self::Lora {
        display_name: "<i><bright-black>lora:</>".to_string(),
        device,
        nonce: None,
        run_mode,
    };
    let lora_future = task::spawn(async move { lora.worker(s).await });
    let _ = lora_future.await?;

    info!("{} 🚩 program terminated", NAME);
    Ok(())
}
