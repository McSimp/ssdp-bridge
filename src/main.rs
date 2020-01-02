use clap::{Arg, App, crate_version, crate_authors, crate_description};
use std::error::Error;
use std::collections::{HashSet, HashMap};
use std::net::{SocketAddrV4, Ipv4Addr};
use std::iter::FromIterator;
use tokio::net::UdpSocket;

// NOTE: This only supports UPnP 1.0
const CACHE_CONTROL: &'static str = "max-age=1800";
const DEFAULT_BIND_IP: &'static str = "0.0.0.0";
const MULTICAST_IP: &'static str = "239.255.255.250";
const SSDP_PORT: u16 = 1900;
const MULTICAST_ADDR: &'static str = "239.255.255.250:1900";

struct UpnpRootDevice {
    uuid: String,
    device_type: String,
    services: Vec<String>
}

fn parse_device_xml(xml: &str) -> Result<UpnpRootDevice, Box<dyn Error>> {
    // Parse xml and sanity check root
    let doc = roxmltree::Document::parse(xml)?;
    let root = doc.root_element();
    if root.tag_name().name() != "root" {
        return Err("root tag is not named 'root'".into());
    }

    // Grab uuid, ensuring that nodes are valid on the way down
    let device = root.children().find(|n| n.has_tag_name("device")).ok_or("missing device node")?;
    let udn = device.children().find(|n| n.has_tag_name("UDN")).ok_or("missing UDN node")?;
    let uuid = udn.text().ok_or("missing UDN text")?;

    // Grab deviceType
    let device_type = device.children().find(|n| n.has_tag_name("deviceType")).ok_or("missing deviceType node")?.text().ok_or("missing deviceType text")?;

    // Grab all the services
    let service_list = device.children().find(|n| n.has_tag_name("serviceList")).ok_or("missing serviceList node")?;
    let services: Result<Vec<String>, Box<dyn Error>> = service_list.children()
        .filter(|n| n.has_tag_name("service"))
        .map(|n| {
            let service_type = n.children().find(|n| n.has_tag_name("serviceType")).ok_or("missing serviceType node")?;
            Ok(service_type.text().ok_or("missing serviceType text")?.to_string())
        }).collect();

    // TODO: Support additional embedded devices in the deviceList tag if it's there

    // Return the device info
    Ok(UpnpRootDevice{
        uuid: uuid.to_string(),
        device_type: device_type.to_string(),
        services: services?
    })
}

fn build_server_header() -> String {
    let info = os_info::get();
    format!(
        "{}/{} UPnP/1.0 {}/{}",
        info.os_type(),
        info.version().version(),
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION")
    )
}

fn build_usn(uuid: &str, service_name: &str) -> String {
    if service_name == uuid {
        uuid.to_owned()
    } else {
        uuid.to_owned() + "::" + service_name
    }
}

fn build_alive_notify(location: &str, server: &str, nt: &str, uuid: &str) -> String {
    format!(
        "NOTIFY * HTTP/1.1\r\n\
         HOST: {}\r\n\
         CACHE-CONTROL: {}\r\n\
         LOCATION: {}\r\n\
         NT: {}\r\n\
         NTS: ssdp:alive\r\n\
         SERVER: {}\r\n\
         USN: {}\r\n\
         \r\n",
        MULTICAST_ADDR,
        CACHE_CONTROL,
        location,
        nt,
        server,
        build_usn(uuid, nt) 
    )
}

fn create_multicast_socket(bind_addr: &SocketAddrV4, multicast_addr: &SocketAddrV4)
    -> Result<UdpSocket, std::io::Error>
{
    // There's no way to set SO_REUSEADDR with standard sockets,
    // so we need to use socket2 to create the socket, set the option
    // then convert it back to a tokio socket.
    use socket2::{Domain, Type, Protocol, Socket, SockAddr};

    let socket = Socket::new(
        Domain::ipv4(),
        Type::dgram(),
        Some(Protocol::udp())
    )?;

    socket.set_reuse_address(true)?;
    socket.bind(&SockAddr::from(*bind_addr))?;
    socket.join_multicast_v4(
        multicast_addr.ip(),
        bind_addr.ip(),
    )?;

    UdpSocket::from_std(socket.into_udp_socket())
}

fn parse_search(data: &str) -> Result<HashMap<String, &str>, Box<dyn Error>> {
    let mut lines = data.lines();
    let mut headers: HashMap<String, &str> = HashMap::new();

    // Ensure it looks like an M-SEARCH request
    if lines.next().ok_or("missing first line")? != "M-SEARCH * HTTP/1.1" {
        return Err("not an M-SEARCH request".into());
    }

    // Parse all the subsequent lines as headers
    for line in lines {
        if let Some(colon_pos) = line.find(":") {
            let header_name = line[..colon_pos].trim().to_ascii_uppercase();
            let header_value = line[colon_pos+1..].trim();
            headers.insert(header_name, header_value);
        }
    }

    Ok(headers)
}

struct SsdpSearchRequest<'a> {
    mx: Option<u8>,
    st: &'a str
}

fn process_ssdp_packet(buf: &[u8]) -> Result<SsdpSearchRequest, Box<dyn Error>> {
    let data = std::str::from_utf8(buf)?;
    let headers = parse_search(data)?;
    println!("{:?}", headers);

    // Check the HOST header is what we expect
    let host = headers.get("HOST").ok_or("missing HOST header")?;
    if *host != MULTICAST_IP && *host != MULTICAST_ADDR {
        return Err("invaild HOST header".into());
    }

    // Check the MAN header is what we expect
    let man = headers.get("MAN").ok_or("missing MAN header")?;
    if *man != "\"ssdp:discover\"" {
        return Err("invaild MAN header".into());
    }
    
    // Grab the ST header
    let st = headers.get("ST").ok_or("missing ST header")?;

    // Grab the MX value as an integer if possible
    let mx = headers.get("MX").and_then(|v| v.parse::<u8>().ok());

    Ok(SsdpSearchRequest {
        mx,
        st
    })
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let matches = App::new("SSDP Bridge")
        .version(crate_version!())
        .author(crate_authors!("\n"))
        .about(crate_description!())
        .arg(Arg::with_name("ip")
            .short("i")
            .long("ip")
            .value_name("IP")
            .takes_value(true)
            .default_value(DEFAULT_BIND_IP)
            .help("Sets IP to bind to"))
        .arg(Arg::with_name("url")
            .short("u")
            .long("url")
            .value_name("URL")
            .takes_value(true)
            .required(true)
            .help("URL for UPnP description of remote root device"))
        .get_matches();

    let bind_addr = SocketAddrV4::new(
        matches.value_of("ip")
            .unwrap()
            .parse::<Ipv4Addr>()
            .expect("Invalid bind IP address"),
        SSDP_PORT
    );

    let url = matches.value_of("url").unwrap();
    let server_header = build_server_header();
    
    // Grab device description from remote URL
    let body = reqwest::get(url).await?.text().await?;
    let upnp_device = parse_device_xml(&body)?;

    // Build all the valid search targets
    let mut search_targets: HashSet<String> = HashSet::from_iter(upnp_device.services);
    search_targets.insert("upnp:rootdevice".to_string());
    search_targets.insert(upnp_device.uuid.clone());
    search_targets.insert(upnp_device.device_type);

    // Setup multicast socket
    let multi: SocketAddrV4 = MULTICAST_ADDR.parse()?;
    let mut socket = create_multicast_socket(&bind_addr, &multi)?;

    // Send out NOTIFY messages for each search target
    for st in &search_targets {
        let data = build_alive_notify(url, &server_header, st, &upnp_device.uuid);
        println!("{:?}", data);
        socket.send_to(data.as_bytes(), multi).await?;
    }

    // Wait for M-SEARCH requests and send out responses
    let mut buf: Vec<u8> = vec![0; 1024];
    loop {
        let (size, src) = socket.recv_from(&mut buf).await?;
        println!("{:?}", std::str::from_utf8(&buf[..size]).unwrap());
        if let Ok(request) = process_ssdp_packet(&buf[..size]) {
            println!("Got valid request! {:?} {:?}", request.st, request.mx);
        }
    }
    
    Ok(())
}
