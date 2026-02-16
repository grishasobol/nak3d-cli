use gsigner::{Address, PrivateKey};

pub mod deploy;

pub struct UserInfo {
    pub address: Address,
    pub sk: PrivateKey,
}

#[derive(Debug)]
pub struct Context {
    pub rpc_url: String,
    pub router_address: Address,
}
