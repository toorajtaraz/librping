//! Fast and multithread Ping Library.
//!
//! [`librpingrs`]: https://github.com/toorajtaraz/librping
extern crate ansi_term;
extern crate pnet;

use ansi_term::Colour::RGB;
use pnet::packet::icmp::echo_reply::EchoReplyPacket;
use pnet::packet::icmp::echo_request;
use pnet::packet::icmp::IcmpTypes;
use pnet::packet::icmpv6::{Icmpv6Types, MutableIcmpv6Packet};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::Packet;
use pnet::packet::{icmp, icmpv6};
use pnet::transport::icmpv6_packet_iter;
use pnet::transport::transport_channel;
use pnet::transport::TransportChannelType::{Layer3, Layer4};
use pnet::transport::TransportProtocol::{Ipv4, Ipv6};
use pnet::transport::*;
use pnet::transport::{TransportReceiver, TransportSender};
use pnet::util;
use pnet_macros_support::types::*;
use rand::random;
use std::collections::BTreeMap;
use std::io::{self, stdout, ErrorKind, Write};
use std::mem;
use std::net::{self, IpAddr};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::{Duration, Instant};

transport_channel_iterator!(
    EchoReplyPacket,
    EchoReplyTransportChannelIterator,
    echo_iter
);

/// This enum is used as state indicator for ping results.
pub enum PingResultState {
    NoReply,
    Replied,
}

/// This struct includes needed data for representing ping results.
pub struct PingResult {
    pub state: PingResultState,
    pub ping_address: IpAddr,
    pub rtt: Duration,
    pub seq: u16,
}

/// This is the same as IpAddr type but with a diffrent name for a more readable code.
pub type AddressToBePinged = IpAddr;

/// This type is a Result consisting of ping struct and receiver handle.
pub type PingRes = Result<(Ping, Receiver<PingResult>), String>;

/// This struct stores all needed data for performing ping task.
pub struct Ping {
    pub max_rtt: Arc<Duration>,
    pub addresses: Arc<Mutex<BTreeMap<AddressToBePinged, (bool, u64, u64, u16, Instant)>>>,
    pub size: usize,
    pub results_sender: Sender<PingResult>,
    pub transport_tx: Arc<Mutex<TransportSender>>,
    pub transport_rx: Arc<Mutex<TransportReceiver>>,
    pub transport_txv6: Arc<Mutex<TransportSender>>,
    pub transport_rxv6: Arc<Mutex<TransportReceiver>>,
    pub tx: Sender<PingResult>,
    pub rx: Arc<Mutex<Receiver<PingResult>>>,
    pub timer: Arc<RwLock<Instant>>,
    pub run: Arc<Mutex<bool>>,
}

/// This block implements Ping struct.
impl Ping {
    /// Creates new Ping and returns PingRes.
    /// It requiers root privileges.
    pub fn new(max_rtt: Option<u16>, size: Option<usize>) -> PingRes {
        let addresses: BTreeMap<AddressToBePinged, (bool, u64, u64, u16, Instant)> =
            BTreeMap::new();
        let (send_handle, recieve_handle) = channel();
        let protocol = Layer4(Ipv4(IpNextHeaderProtocols::Icmp));
        let (transport_tx, transport_rx) = match transport_channel(4096, protocol) {
            Ok((tx, rx)) => (tx, rx),
            Err(e) => return Err(e.to_string()),
        };

        let protocolv6 = Layer4(Ipv6(IpNextHeaderProtocols::Icmpv6));
        let (transport_txv6, transport_rxv6) = match transport_channel(4096, protocolv6) {
            Ok((txv6, rxv6)) => (txv6, rxv6),
            Err(e) => return Err(e.to_string()),
        };

        let (tx, rx) = channel();

        let mut ping = Ping {
            max_rtt: Arc::new(Duration::from_millis(2000)),
            addresses: Arc::new(Mutex::new(addresses)),
            size: 64,
            results_sender: send_handle,
            transport_tx: Arc::new(Mutex::new(transport_tx)),
            transport_rx: Arc::new(Mutex::new(transport_rx)),
            transport_txv6: Arc::new(Mutex::new(transport_txv6)),
            transport_rxv6: Arc::new(Mutex::new(transport_rxv6)),
            rx: Arc::new(Mutex::new(rx)),
            tx,
            timer: Arc::new(RwLock::new(Instant::now())),
            run: Arc::new(Mutex::new(false)),
        };

        if let Some(rtt_value) = max_rtt {
            if rtt_value == 0 {
                return Err(String::from("BAX MAX RTT"));
            }
            ping.max_rtt = Arc::new(Duration::from_millis(rtt_value as u64));
        }

        if let Some(size) = size {
            if size < 12 {
                return Err(String::from("BAX SIZE - MIN=12"));
            }
            ping.size = size;
        }

        Ok((ping, recieve_handle))
    }

    /// This function adds hosts to be pinged.
    /// You can add new hosts even when other hosts are being pinged.
    pub fn add_address(&self, addr: IpAddr) {
        self.addresses
            .lock()
            .unwrap()
            .insert(addr, (true, 0, 0, 0, Instant::now()));
    }

    /// This function starts ping task based on Ping struc's configs.
    pub fn run_pings(&self) {
        let rx = self.rx.clone();
        let transport_tx = self.transport_tx.clone();
        let transport_txv6 = self.transport_txv6.clone();
        let results_sender = self.results_sender.clone();
        let stop = self.run.clone();
        let addrs = self.addresses.clone();
        let timer = self.timer.clone();
        let max_rtt = self.max_rtt.clone();
        let size = self.size;

        {
            let mut run = self.run.lock().unwrap();
            *run = true;
        }
        thread::spawn(move || {
            do_ping(
                size,
                timer,
                stop,
                results_sender,
                rx,
                transport_tx,
                transport_txv6,
                addrs,
                max_rtt,
            );
        });
    }

    /// This function is responsible for listening for ICMP ECHO REPLIES.
    pub fn start_listening(&self) {
        let tx = self.tx.clone();
        let transport_rx = self.transport_rx.clone();
        let run = self.run.clone();
        let addresses = self.addresses.clone();
        let max_rtt = self.max_rtt.clone();
        thread::spawn(move || {
            let mut receiver = transport_rx.lock().unwrap();
            let mut iter = echo_iter(&mut receiver);
            loop {
                match iter.next() {
                    Ok((packet, addr)) => {
                        if packet.get_icmp_type() == icmp::IcmpType::new(0) {
                            let start_time: Instant;
                            match addresses.lock().unwrap().get(&addr) {
                                Some((_, _, _, _, addr_timer)) => {
                                    start_time = *addr_timer;
                                    if Instant::now().duration_since(start_time) > *max_rtt {
                                        continue;
                                    }
                                }
                                _ => {
                                    continue;
                                }
                            }
                            match tx.send(PingResult {
                                state: PingResultState::Replied,
                                ping_address: addr,
                                rtt: Instant::now().duration_since(start_time),
                                seq: packet.get_sequence_number(),
                            }) {
                                Ok(_) => {}
                                Err(e) => {
                                    if *run.lock().unwrap() {
                                        panic!("{}", e.to_string());
                                    }
                                }
                            }
                        } else {
                            println!(
                                "UNEXPECTED ICMP PACKET RECIEVED ==> {:?}",
                                packet.get_icmp_type()
                            );
                        }
                    }
                    Err(e) => {
                        panic!("{}", e.to_string());
                    }
                }
            }
        });

        let txv6 = self.tx.clone();
        let transport_rxv6 = self.transport_rxv6.clone();
        let runv6 = self.run.clone();
        let addresses = self.addresses.clone();
        let max_rtt = self.max_rtt.clone();

        thread::spawn(move || {
            let mut receiver = transport_rxv6.lock().unwrap();
            let mut iter = icmpv6_packet_iter(&mut receiver);
            loop {
                match iter.next() {
                    Ok((packet, addr)) => {
                        if packet.get_icmpv6_type() == icmpv6::Icmpv6Type::new(129) {
                            let start_time: Instant;
                            match addresses.lock().unwrap().get(&addr) {
                                Some((_, _, _, _, addr_timer)) => {
                                    start_time = *addr_timer;
                                    if Instant::now().duration_since(start_time) > *max_rtt {
                                        continue;
                                    }
                                }
                                _ => {
                                    continue;
                                }
                            }
                            match txv6.send(PingResult {
                                state: PingResultState::Replied,
                                ping_address: addr,
                                rtt: Instant::now().duration_since(start_time),
                                seq: 0,
                            }) {
                                Ok(_) => {}
                                Err(e) => {
                                    if !*runv6.lock().unwrap() {
                                        panic!("{}", e.to_string());
                                    }
                                }
                            }
                        } else {
                        }
                    }
                    Err(e) => {
                        panic!("{}", e.to_string());
                    }
                }
            }
        });
    }
}

fn send_echo(
    tx: &mut TransportSender,
    addr: IpAddr,
    size: usize,
    seq: u16,
) -> Result<usize, std::io::Error> {
    let mut vec: Vec<u8> = vec![0; size];
    let mut echo_packet = echo_request::MutableEchoRequestPacket::new(&mut vec[..]).unwrap();
    echo_packet.set_sequence_number(seq);
    echo_packet.set_identifier(random::<u16>());
    echo_packet.set_icmp_type(IcmpTypes::EchoRequest);
    let csum = icmp_checksum(&echo_packet);
    echo_packet.set_checksum(csum);

    tx.send_to(echo_packet, addr)
}

fn send_echov6(
    tx: &mut TransportSender,
    addr: IpAddr,
    size: usize,
) -> Result<usize, std::io::Error> {
    let mut vec: Vec<u8> = vec![0; size];

    let mut echo_packet = MutableIcmpv6Packet::new(&mut vec[..]).unwrap();
    echo_packet.set_icmpv6_type(Icmpv6Types::EchoRequest);

    let csum = icmpv6_checksum(&echo_packet);
    echo_packet.set_checksum(csum);

    tx.send_to(echo_packet, addr)
}

fn icmp_checksum(packet: &echo_request::MutableEchoRequestPacket) -> u16be {
    util::checksum(packet.packet(), 1)
}

fn icmpv6_checksum(packet: &MutableIcmpv6Packet) -> u16be {
    util::checksum(packet.packet(), 1)
}

fn do_ping(
    size: usize,
    timer: Arc<RwLock<Instant>>,
    run: Arc<Mutex<bool>>,
    results_sender: Sender<PingResult>,
    thread_rx: Arc<Mutex<Receiver<PingResult>>>,
    tx: Arc<Mutex<TransportSender>>,
    txv6: Arc<Mutex<TransportSender>>,
    addresses: Arc<Mutex<BTreeMap<AddressToBePinged, (bool, u64, u64, u16, Instant)>>>,
    max_rtt: Arc<Duration>,
) {
    let mut min_rtt_r = std::f64::MAX;
    let mut max_rtt_r = std::f64::MIN;
    loop {
        for (address, (has_answered, send, _, seq, addr_timer)) in
            addresses.lock().unwrap().iter_mut()
        {
            match if address.is_ipv4() {
                *send += 1;
                *seq += 1;
                *addr_timer = Instant::now();
                send_echo(&mut tx.lock().unwrap(), *address, size, *seq)
            } else if address.is_ipv6() {
                *send += 1;
                *addr_timer = Instant::now();
                send_echov6(&mut txv6.lock().unwrap(), *address, size)
            } else {
                Ok(0)
            } {
                Err(e) => {
                    println!(
                        "{}",
                        RGB(255, 70, 70).paint(format!(
                            "Failed to send ping to {:?}: {}",
                            (*address),
                            e
                        ))
                    );
                }
                _ => {}
            }
            *has_answered = false;
        }
        {
            let mut timer = timer.write().unwrap();
            *timer = Instant::now();
        }
        loop {
            let start_time = timer.read().unwrap();
            if Instant::now().duration_since(*start_time) > *max_rtt {
                break;
            }
            match thread_rx
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_millis(100))
            {
                Ok(result) => match result {
                    PingResult {
                        ping_address: addr,
                        rtt: _,
                        state: PingResultState::Replied,
                        seq: seq_num,
                    } => {
                        let ref mut targets = addresses.lock().unwrap();
                        let res = targets.get_mut(&addr);
                        if let Some((target, _, recieved, seq, _)) = res {
                            if *seq != seq_num {
                                continue;
                            }
                            *target = true;
                            *recieved += 1;
                            if result.rtt.as_secs_f64() > max_rtt_r {
                                max_rtt_r = result.rtt.as_secs_f64();
                            }
                            if result.rtt.as_secs_f64() < min_rtt_r {
                                min_rtt_r = result.rtt.as_secs_f64();
                            }
                            match results_sender.send(result) {
                                Ok(_) => {}
                                Err(e) => {
                                    if *run.lock().unwrap() {
                                        panic!("Error sending ping result on channel: {}", e)
                                    }
                                }
                            }
                        }
                    }
                    _ => {}
                },
                Err(_) => {}
            }
        }
        for (address, (has_answered, _, _, _, _)) in addresses.lock().unwrap().iter() {
            if *has_answered == false {
                match results_sender.send(PingResult {
                    ping_address: *address,
                    state: PingResultState::NoReply,
                    rtt: Duration::new(0, 0),
                    seq: 0,
                }) {
                    Ok(_) => {}
                    Err(e) => {
                        if *run.lock().unwrap() {
                            panic!("Error sending ping Idle result on channel: {}", e)
                        }
                    }
                }
            }
        }
        if !(*run.lock().unwrap()) {
            stdout().flush().unwrap();
            println!(
                "\n{}",
                RGB(1, 204, 204).paint("-------------statistics------------")
            );
            for (address, (_, send, recieved, _, _)) in addresses.lock().unwrap().iter() {
                println!(
                    "For IP<{}> <{}> packet(s) sent and <{}> packet(s) recieved, loss = {}%",
                    RGB(223, 97, 0).paint(format!("{}", address)),
                    RGB(255, 255, 51).paint(format!("{}", send)),
                    RGB(51, 255, 51).paint(format!("{}", recieved)),
                    RGB(255, 102, 102).paint(format!("{}", ((send - recieved) * 100) / send))
                );
            }
            println!(
                "MINIMUM RTT=<{}>ms, MAXIMUM RTT=<{}>ms",
                RGB(178, 102, 255).paint(format!("{}", min_rtt_r * 1000.0)),
                RGB(178, 102, 255).paint(format!("{}", max_rtt_r * 1000.0))
            );
            std::process::exit(0x0100);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    fn am_root() -> bool {
        match env::var("USER") {
            Ok(val) => val == "root",
            Err(_) => false,
        }
    }

    #[test]
    fn create_new_ping_util() {
        if am_root() {
            let (_, _) = Ping::new(Some(2000), Some(128)).unwrap();
        } else {
            writeln!(
                &mut io::stdout(),
                "The test 'create_new_ping_util' was skipped as it needs to be run as root"
            )
            .unwrap();
        }
    }

    #[test]
    #[should_panic]
    fn create_bad_ping_util() {
        if am_root() {
            let (_, _) = Ping::new(Some(2000), Some(128)).unwrap();
        } else {
            writeln!(
                &mut io::stdout(),
                "The test 'create_bad_ping_util' was skipped as it needs to be run as root"
            )
            .unwrap();
            panic!();
        }
    }
}
