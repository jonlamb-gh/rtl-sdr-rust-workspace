use chrono::{DateTime, Utc};
use crossbeam::crossbeam_channel;
use err_derive::Error;
use influx_db_client::{Client, Point, Precision, Value};
use log::{debug, error, info, warn};
use smart_meter_parser::{protocols::*, Decoder, ProtocolParser, ScmParser};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::{io, process};
use structopt::StructOpt;

#[derive(Debug, Clone, PartialEq, StructOpt)]
#[structopt(
    name = "smart-meter-detector",
    about = "Detect and log smart meter detections"
)]
pub struct Opts {
    /// RTL-SDR device index
    #[structopt(short = "i", long, default_value = "0", env = "RTL_DEVICE_INDEX")]
    pub device_index: u32,

    /// Influxdb collector address:port
    #[structopt(
        short = "r",
        long,
        default_value = "http://localhost:8086",
        env = "INFLUXDB_REMOTE"
    )]
    pub remote: String,

    /// Database name
    #[structopt(short = "d", long, default_value = "smart-meters")]
    pub database: String,

    /// Measurement name
    #[structopt(short = "m", long, default_value = "detection")]
    pub measurement_name: String,

    /// Location tag
    #[structopt(short = "l", long, default_value = "None")]
    pub location_tag: String,

    /// Don't conect to remote
    #[structopt(long)]
    pub no_remote: bool,
    // TODO - make --remote an Option, None means no_remote
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct Samples {
    pub iq_data: Vec<u8>,
}

#[derive(Clone, PartialEq, PartialOrd, Debug)]
pub struct Messages {
    pub time: DateTime<Utc>,
    pub rms_power_max: f64,
    pub rms_power_mean: f64,
    pub messages: Vec<Scm>,
}

#[derive(Clone, PartialEq, PartialOrd, Debug)]
pub struct Detection {
    pub time: DateTime<Utc>,
    pub id: u32,
    pub commodity_type: u8,
    pub physical_tamper: u8,
    pub encoder_tamper: u8,
    pub consumption: u32,
    pub rms_power_max: f64,
    pub rms_power_mean: f64,
    pub location: String,
}

fn main() -> Result<(), Error> {
    let opts = Opts::from_args();
    env_logger::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let result = run(opts);
    if let Err(e) = &result {
        print_error(e);
    }

    result
}

fn run(opts: Opts) -> Result<(), Error> {
    info!("Remote: {}", opts.remote);
    info!("Database: {}", opts.database);
    info!("Measurement name: {}", opts.measurement_name);
    info!("Location tag: {}", opts.location_tag);

    let client = Client::new(opts.remote, opts.database.clone());
    //.set_authentication("root", "root");

    if !opts.no_remote {
        debug!("Creating database {}", &opts.database);
        client.create_database(&opts.database)?;
    }

    let (mut ctl, mut reader) = rtlsdr_mt::open(opts.device_index)?;

    let default_config = DeviceConfig {
        center_freq: ScmParser::PACKET_CONFIG.center_freq as _,
        sample_rate: ScmParser::PACKET_CONFIG.sample_rate() as _,
        bandwidth: 0,
        //bandwidth: 4_000_000,
        agc: true,
    };

    default_config.apply(&mut ctl)?;

    let running = Arc::new(AtomicUsize::new(0));
    let r = running.clone();
    let r_decode_thread = running.clone();
    ctrlc::set_handler(move || {
        let prev = r.fetch_add(1, Ordering::SeqCst);
        if prev == 0 {
            ctl.cancel_async_read();
            info!("Shutting down");
        } else {
            warn!("Forcing exit");
            process::exit(0);
        }
    })?;

    let pkt_cfg = ScmParser::PACKET_CONFIG;

    let (samples_tx, samples_rx) = crossbeam_channel::unbounded();

    // TODO - try the synchronous interface
    let recv_thread = std::thread::spawn(move || {
        info!("Recv thread started");

        let input_size = pkt_cfg.input_size();

        // input_size() == 8192 (block_size2)
        reader
            .read_async(4, 32768, |bytes| {
                assert!(bytes.len() % input_size == 0);
                let samples = Samples {
                    iq_data: bytes.to_vec(),
                };
                samples_tx
                    .send(samples)
                    .map_err(|_| warn!("Recv send error"))
                    .ok();
            })
            .expect("Device read");
        info!("Recv thread done");
    });

    let (msg_tx, msg_rx) = crossbeam_channel::unbounded();

    let decode_thread = std::thread::spawn(move || {
        info!("Decode thread started");

        let mut dec = Decoder::new(ScmParser);

        while r_decode_thread.load(Ordering::SeqCst) == 0 {
            let samples = if let Ok(s) = samples_rx.recv() {
                s
            } else {
                break;
            };

            let time = Utc::now();

            let mut messages = Vec::new();
            for chunk in samples.iq_data.chunks_exact(dec.input_size()) {
                for msg in dec.decode(&chunk[..]).iter() {
                    //debug!("{:?}", msg);
                    messages.push(*msg);
                }
            }

            if !messages.is_empty() {
                let (rms_power_max, rms_power_mean) = dec.last_rms_power();
                msg_tx
                    .send(Messages {
                        time,
                        rms_power_max,
                        rms_power_mean,
                        messages,
                    })
                    .expect("Decoder send");
            }
        }

        info!("Decode thread done");
    });

    while running.load(Ordering::SeqCst) == 0 {
        let msg = if let Ok(m) = msg_rx.recv() {
            m
        } else {
            warn!("Rx error exit");
            break;
        };

        debug!("Processing {:?}", msg);

        if !opts.no_remote {
            let rms_power_max = msg.rms_power_max;
            let rms_power_mean = msg.rms_power_mean;
            let recv_time = msg.time;
            for m in msg.messages.iter() {
                let mut point = Point::new(&opts.measurement_name);
                point.add_timestamp(recv_time.timestamp());
                //point.add_field("id", Value::Integer(m.id.get() as _));
                point.add_field("physical_tamper", Value::Integer(m.physical_tamper as _));
                point.add_field("encoder_tamper", Value::Integer(m.encoder_tamper as _));
                point.add_field("consumption", Value::Integer(m.consumption as _));
                point.add_field("rms_power_max", Value::Float(rms_power_max));
                point.add_field("rms_power_mean", Value::Float(rms_power_mean));
                point.add_tag("id", Value::Integer(m.id.get() as _));
                point.add_tag(
                    "commodity_type",
                    Value::Integer(u8::from(m.commodity_type) as _),
                );
                point.add_tag("location", Value::String(opts.location_tag.clone()));

                debug!("Database point {:?}", point);

                // TODO - batch write all the recv'd messages
                let result = client.write_point(point, Some(Precision::Seconds), None);
                if let Err(e) = result {
                    warn!("Failed to write db {:?}", e);
                }
            }
        }
    }

    running.fetch_add(1, Ordering::SeqCst);
    std::thread::sleep(std::time::Duration::from_secs(1));
    recv_thread.join().expect("Recv thread join failed");
    decode_thread.join().expect("Decode thread join failed");

    info!("All done");

    Ok(())
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct DeviceConfig {
    center_freq: u32,
    sample_rate: u32,
    bandwidth: u32, // zero means auto
    agc: bool,
}

impl DeviceConfig {
    pub fn apply(&self, controller: &mut rtlsdr_mt::Controller) -> Result<(), rtlsdr_mt::Error> {
        info!("Applying {:?}", self);
        controller.set_center_freq(self.center_freq)?;
        controller.set_sample_rate(self.sample_rate)?;
        controller.set_bandwidth(self.bandwidth)?;
        if self.agc {
            controller.enable_agc()?;
        } else {
            controller.disable_agc()?;
        }
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum Error {
    #[error(display = "Encountered an IO error: {}", _0)]
    Io(io::Error),

    #[error(display = "Encountered a database error: {}", _0)]
    Database(influx_db_client::Error),

    #[error(display = "Encountered a device error: {:?}", _0)]
    Device(rtlsdr_mt::Error),

    #[error(display = "Encountered a ctrlc error: {}", _0)]
    Ctrlc(ctrlc::Error),
}

fn print_error(e: &dyn std::error::Error) {
    error!("{}", e);
    let mut cause = e.source();
    while let Some(e) = cause {
        error!("Caused by: {}", e);
        cause = e.source();
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<influx_db_client::Error> for Error {
    fn from(e: influx_db_client::Error) -> Self {
        Error::Database(e)
    }
}

impl From<rtlsdr_mt::Error> for Error {
    fn from(_e: rtlsdr_mt::Error) -> Self {
        Error::Device(())
    }
}

impl From<ctrlc::Error> for Error {
    fn from(e: ctrlc::Error) -> Self {
        Error::Ctrlc(e)
    }
}
