use bit_vec::BitVec;
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::fs::File;
use std::io::Read;
use std::net::{UdpSocket, SocketAddr };
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::time::Duration;

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
	fn req_missing(&mut self, socket: &UdpSocket, src: SocketAddr)  {
		while { 
			self.next_missing += 1;
			self.next_missing %= blocks(self.len);
			self
			.bitmap
			.get(self.next_missing as usize)
			.unwrap()
		} {}
		if self.next_missing > self.highest_seen && self.lastreq+1 < blocks(self.len) {
			self.lastreq+=1;
			self.next_missing=self.lastreq;
//			if self.next_missing>=self.len {
//				return;
//			}  should really do nothing here, not request more, it'll be dups, we're on the tail
		}
		let mut request_packet = RequestPacket {
            offset: 0,
            hash: self.hash,
        };
		request_packet.offset = self.next_missing;
		let encoded: Vec<u8> = bincode::serialize(&request_packet).unwrap();
		socket.send_to(&encoded[..], &src).expect("cant send_to");
		self.requested += 1;
	}
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct ContentPacket {
    len: u64,
    offset: u64,
    hash: [u8; 32],
    data: [u8; 32], // something about serde being limited to 32 byte u8s??  i took a wrong turn there i guess
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
    let mut file = File::open(pathname)?;
    let metadata = fs::metadata(&pathname).expect("unable to read metadata");
    let mut buffer = [0; 32]; // vec![0; 32 as usize];
    file.read(&mut buffer).expect("buffer overflow");
    let mut started = false;
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
            let mut buf = [0; 1500]; //	[0; ::std::mem::size_of::ContentPacket];
            match socket.recv_from(&mut buf) {
				Ok(_r) => true,
				Err(_e) => { 
					started=false;
					println!("stalled, bumping");
					continue;
				},
			};
//            let (_amt, _src) = socket.recv_from(&mut buf).expect("socket error");
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

fn send_block(mut content_packet: ContentPacket, host: &String, socket: &UdpSocket, file: &File) {
    file.read_at(&mut content_packet.data, content_packet.offset * 32)
        .expect("cant read");
    let encoded: Vec<u8> = bincode::serialize(&content_packet).unwrap();
    socket.send_to(&encoded[..], host).expect("cant send_to");
}

fn blocks(len: u64) -> u64 {
    return (len + 32 - 1) / 32;
}

fn receive() -> Result<bool, std::io::Error> {
    let socket = UdpSocket::bind("0.0.0.0:34254").expect("bind failed");
    use std::collections::HashMap;
    let mut inbound_states = HashMap::new();
    loop {
        let mut buf = [0; 1500]; //	[0; ::std::mem::size_of::ContentPacket];
        let (_amt, src) = socket.recv_from(&mut buf).expect("socket error");
        let content_packet: ContentPacket = bincode::deserialize(&buf).unwrap();
        println!("received block: {:?}", content_packet.offset);
        if !inbound_states.contains_key(&hex::encode(content_packet.hash)) {
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
            inbound_states.insert(hex::encode(content_packet.hash), inbound_state);
        }
        let mut inbound_state = inbound_states
            .get_mut(&hex::encode(content_packet.hash))
            .unwrap();
        inbound_state
            .file
            .write_at(&content_packet.data, content_packet.offset * 32)
            .expect("cant write");
        if inbound_state
            .bitmap
            .get(content_packet.offset as usize)
            .unwrap()
        {
            println!("dup: {:?}", content_packet.offset);
        } else {
			inbound_state.blocks_remaining-=1;
		}
        if content_packet.offset > inbound_state.highest_seen {
            inbound_state.highest_seen = content_packet.offset
        }
        inbound_state
            .bitmap
            .set(content_packet.offset as usize, true);
        
		let mut request_packet = RequestPacket {
            offset: 0,
            hash: content_packet.hash,
        };

        if inbound_state.blocks_remaining == 0 { 
            // upload done
            inbound_state.file.set_len(inbound_state.len)?;
            println!("received {:?}",content_packet.hash);
            //			inbound_states.remove(&hex::encode(content_packet.hash));  this will just start over if packets are in flight, so it needs a delay
			request_packet.offset = !0; 
			let encoded: Vec<u8> = bincode::serialize(&request_packet).unwrap();
			socket.send_to(&encoded[..], &src).expect("cant send_to");
            continue;
        }

        inbound_state.lastreq += 1;
        if inbound_state.lastreq >= blocks(inbound_state.len) {
            // "done" but just filling in holes now
            inbound_state.req_missing(&socket, src );
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
