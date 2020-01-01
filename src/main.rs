use std::error::Error;

struct UpnpDevice {
    uuid: String,
    services: Vec<String>
}

fn parse_device_xml(xml: &str) -> Result<UpnpDevice, Box<dyn Error>> {
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

    // Grab all the services
    let service_list = device.children().find(|n| n.has_tag_name("serviceList")).ok_or("missing serviceList node")?;
    let services: Result<Vec<String>, Box<dyn Error>> = service_list.children()
        .filter(|n| n.has_tag_name("service"))
        .map(|n| {
            let service_type = n.children().find(|n| n.has_tag_name("serviceType")).ok_or("missing serviceType node")?;
            Ok(service_type.text().ok_or("missing serviceType text")?.to_string())
        }).collect();

    // Return the device info
    Ok(UpnpDevice{
        uuid: uuid.to_string(),
        services: services?
    })
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let body = reqwest::get("http://10.10.0.100:32469/DeviceDescription.xml")
        .await?
        .text()
        .await?;

    let upnp_device = parse_device_xml(&body)?;
    
    Ok(())
}
