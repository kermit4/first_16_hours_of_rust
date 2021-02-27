use bit_vec::BitVec;
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::fs::File;
use std::net::{SocketAddr, UdpSocket};
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::time::Duration;
use std::mem::transmute;

struct InboundState {
    file: File,
    len: u64,
    hash: [u8; 32],
    blocks_remaining: u64,
    next_missing: u64,
    requested: u64,
    highest_seen: u64,
    bitmap: BitVec,
    lastreq: u64,
}

impl InboundState {
    fn req_missing(&mut self, socket: &UdpSocket, src: SocketAddr) {
        if self.next_missing > self.highest_seen {
            self.next_missing = 0;
        }
        while {
            self.next_missing += 1;
            self.next_missing %= blocks(self.len);
            self.bitmap.get(self.next_missing as usize).unwrap()
        } {}
        if self.next_missing > self.highest_seen {
            // nothing missing
            if self.lastreq + 1 >= blocks(self.len) {
                // on the tail, dont dup the window
                return;
            }
            self.lastreq += 1; // just increase window
            self.next_missing = self.lastreq;
        }
        let mut request_packet = RequestPacket {
            offset: 0,
            hash: self.hash,
        };
        request_packet.offset = self.next_missing;
        println!("requesting block {:?}", request_packet.offset);
        let encoded: Vec<u8> = bincode::serialize(&request_packet).unwrap();
        socket.send_to(&encoded[..], &src).expect("cant send_to");
        self.requested += 1;
    }
}

#[repr(C)] 
//#[derive(Copy,Clone)]
struct ContentPacket {
    len: u64,
    offset: u64,
    hash: [u8; 32],
    data: [u8; ContentPacket::block_size() as usize], // serde had a strange 32 byte limit.  also serde would not be a portable network protocol format.
}

impl ContentPacket {
	const fn block_size() -> u64 {
		64 // intentionally small for faster testing
	}
}


#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct RequestPacket {
    offset: u64,
    hash: [u8; 32],
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() > 2 {
        send(&args[1], &args[2]).expect("send()");
    } else {
        receive().expect("receive");
    }
}

fn send(pathname: &String, host: &String) -> Result<bool, std::io::Error> {
    let socket = UdpSocket::bind("0.0.0.0:0").expect("bind failed");
    socket.set_read_timeout(Some(Duration::new(5, 0)))?;
    let file = File::open(pathname)?;
    let metadata = fs::metadata(&pathname).expect("unable to read metadata");
    let buffer = [0; ContentPacket::block_size() as usize]; // vec![0; 32 as usize];
    let mut started = false;

	fn send_block(mut content_packet: ContentPacket, host: &String, socket: &UdpSocket, file: &File) {
		file.read_at(&mut content_packet.data, content_packet.offset * ContentPacket::block_size())
			.expect("cant read");
		let encoded: [u8;std::mem::size_of::<ContentPacket>()] = unsafe {  transmute(content_packet) };
		socket.send_to(&encoded[..], host).expect("cant send_to");
	}

    loop {
        let mut hash = [0u8; 32];
        hex::decode_to_slice(
            "f000000000000000f000000000000000f000000000000000f000000000000000",
            &mut hash as &mut [u8],
        )
        .expect("not hex"); // not the real hash obviously
        if !started {
            let content_packet = ContentPacket {
                len: metadata.len(),
                offset: 0,
                hash: hash,
                data: buffer,
            };
            started = true;
            send_block(content_packet, host, &socket, &file);
        } else {
            let mut buf = [0; std::mem::size_of::<ContentPacket>()];
            match socket.recv_from(&mut buf) {
                Ok(_r) => true,
                Err(_e) => {
                    started = false;
                    println!("stalled, bumping");
                    continue;
                }
            };
            let req: RequestPacket = bincode::deserialize(&buf).unwrap();
            if req.offset == !0 {
                println!("sent!");
                std::process::exit(0);
            }
            println!("sending block: {:?}", req.offset);
            let content_packet = ContentPacket {
                len: metadata.len(),
                offset: req.offset,
                hash: hash,
                data: buffer,
            };
            send_block(content_packet, host, &socket, &file);
        }
    }
}

fn blocks(len: u64) -> u64 {
    return (len + ContentPacket::block_size() - 1) / ContentPacket::block_size();
}

fn receive() -> Result<bool, std::io::Error> {
    let socket = UdpSocket::bind("0.0.0.0:34254").expect("bind failed");
    use std::collections::HashMap;
    let mut inbound_states = HashMap::new();
    loop {
        let mut buf = [0; std::mem::size_of::<ContentPacket>()]; //	[0; ::std::mem::size_of::ContentPacket];
        let (_amt, src) = socket.recv_from(&mut buf).expect("socket error");
        let content_packet: ContentPacket = unsafe { transmute(buf) };
        println!("received block: {:?}", content_packet.offset);
        if !inbound_states.contains_key(&content_packet.hash) {
            // new upload
            let inbound_state = InboundState {
                lastreq: 0,
                file: File::create(Path::new(&hex::encode(content_packet.hash)))?,
                len: content_packet.len,
                blocks_remaining: blocks(content_packet.len),
                next_missing: 0,
                highest_seen: 0,
                hash: content_packet.hash,
                requested: 0,
                bitmap: BitVec::from_elem(blocks(content_packet.len) as usize, false),
            };
            inbound_states.insert(content_packet.hash, inbound_state);
        }
        let mut inbound_state = inbound_states.get_mut(&content_packet.hash).unwrap();
        inbound_state
            .file
            .write_at(&content_packet.data, content_packet.offset * ContentPacket::block_size())
            .expect("cant write");
        if inbound_state
            .bitmap
            .get(content_packet.offset as usize)
            .unwrap()
        {
            println!("dup: {:?}", content_packet.offset);
        } else {
            inbound_state.blocks_remaining -= 1;
			inbound_state
				.bitmap
				.set(content_packet.offset as usize, true);
			if content_packet.offset > inbound_state.highest_seen {
				inbound_state.highest_seen = content_packet.offset
			}
        }

        let mut request_packet = RequestPacket {
            offset: 0,
            hash: content_packet.hash,
        };

        if inbound_state.blocks_remaining == 0 {
            // upload done
            inbound_state.file.set_len(inbound_state.len)?;
            println!("received {:?}", &hex::encode(&content_packet.hash));
            //			inbound_states.remove(&hex::encode(content_packet.hash));  this will just start over if packets are in flight, so it needs a delay
            request_packet.offset = !0;
            let encoded: Vec<u8> = bincode::serialize(&request_packet).unwrap();
            socket.send_to(&encoded[..], &src).expect("cant send_to");
            continue;
        }

        inbound_state.lastreq += 1;
        if inbound_state.lastreq >= blocks(inbound_state.len) {
            // "done" but just filling in holes now
            inbound_state.req_missing(&socket, src);
            continue;
        }

        request_packet.offset = inbound_state.lastreq;
        println!("requesting block {:?}", request_packet.offset);
        let encoded: Vec<u8> = bincode::serialize(&request_packet).unwrap();
        socket.send_to(&encoded[..], &src).expect("cant send_to");
        inbound_state.requested += 1;

        if (inbound_state.requested % 100) == 0 {
            // push it to 1% packet loss
            inbound_state.req_missing(&socket, src);
        }
    }
}
