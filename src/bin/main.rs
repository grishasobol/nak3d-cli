use alloy::providers::RootProvider;
use anyhow::{Context, Result, anyhow, bail, ensure};
use clap::{Args, Parser, Subcommand};
use directories::ProjectDirs;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    str::FromStr,
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const APP_QUALIFIER: &str = "com";
const APP_ORGANIZATION: &str = "Gear";
const APP_NAME: &str = "nak3d-cli";

#[derive(Debug, Parser)]
#[command(name = "nak3d-cli")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Login a user by Ethereum address or existing user name.
    Login(LoginArgs),
    /// Set mutable configuration values.
    Set(SetArgs),
    /// Show current app state from local DB.
    ShowState,

    UploadCode(UploadCodeArgs),
    CreateNewContract(CreateNewContractArgs),

    // TODO:
    /// Query profiles from the contract via RPC (stub).
    GetProfiles(GetProfilesArgs),
    /// Upload hidden content (stub) and save local ContentId -> PreProof mapping.
    UploadHiddenContent(UploadHiddenContentArgs),
    /// Start model-side continuous client loop.
    RunModelClient(RunModelClientArgs),
    /// Buy hidden content from a model and save purchase status.
    BuyHiddenContent(BuyHiddenContentArgs),
}

#[derive(Debug, Args)]
struct UploadCodeArgs {
    /// Path to the Wasm file containing the model code.
    #[arg(value_name = "WASM_PATH")]
    wasm_path: PathBuf,
}

#[derive(Debug, Args)]
struct CreateNewContractArgs {
    #[arg(value_name = "CodeId")]
    code_id: String,
}

#[derive(Debug, Args)]
struct LoginArgs {
    /// Ethereum address (for create/login) or existing user name.
    user: String,
    /// Required for first login when creating a new user by address.
    #[arg(long)]
    name: Option<String>,
    /// Required for first login when creating a new user by address.
    #[arg(long)]
    private_key: Option<String>,
}

#[derive(Debug, Args)]
struct SetArgs {
    #[command(subcommand)]
    command: SetCommand,
}

#[derive(Debug, Subcommand)]
enum SetCommand {
    /// Set router address used by other commands.
    RouterAddress { address: String },
    /// Set contract address used by other commands.
    ContractAddress { address: String },
    /// Set RPC URL used by other commands.
    RpcUrl { url: String },
}

#[derive(Debug, Args)]
struct GetProfilesArgs {}

#[derive(Debug, Args)]
struct UploadHiddenContentArgs {
    /// Content ID from contract domain model.
    #[arg(long)]
    content_id: u64,
    /// Local pre-proof to store for future replies.
    #[arg(long)]
    pre_proof: String,
}

#[derive(Debug, Args)]
struct RunModelClientArgs {
    /// Polling interval for waiting purchase requests.
    #[arg(long, default_value_t = 10)]
    poll_interval_secs: u64,
    /// Optional finite run mode; if omitted, loop is continuous.
    #[arg(long)]
    max_iterations: Option<u64>,
}

#[derive(Debug, Args)]
struct BuyHiddenContentArgs {
    /// Model address that owns the content.
    #[arg(long)]
    model_address: String,
    /// Content id to buy.
    #[arg(long)]
    content_id: u64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct AppState {
    current_user_address: Option<String>,
    contract_address: Option<String>,
    rpc_url: Option<String>,
    router_address: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct UserRecord {
    eth_address: String,
    name: String,
    private_key: String,
    content_preproofs: BTreeMap<u64, String>,
    purchases: Vec<PurchaseRecord>,
}

impl UserRecord {
    fn new(eth_address: String, name: String, private_key: String) -> Self {
        Self {
            eth_address,
            name,
            private_key,
            content_preproofs: BTreeMap::new(),
            purchases: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum PurchaseStatus {
    Pending,
    Completed,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PurchaseRecord {
    id: u64,
    model_address: String,
    content_id: u64,
    status: PurchaseStatus,
    user_balance: u128,
    contract_balance: u128,
    model_balance: u128,
    created_at_unix_secs: u64,
    updated_at_unix_secs: u64,
}

struct Db {
    root_dir: PathBuf,
    users_dir: PathBuf,
    state_path: PathBuf,
    state: AppState,
}

impl Db {
    fn load() -> Result<Self> {
        let root_dir = default_data_dir()?;
        let users_dir = root_dir.join("users");
        let state_path = root_dir.join("state.json");

        fs::create_dir_all(&users_dir).with_context(|| {
            format!(
                "failed to create users directory at {}",
                users_dir.display()
            )
        })?;

        let state = read_json_or_default(&state_path)
            .with_context(|| format!("failed to read state from {}", state_path.display()))?;

        Ok(Self {
            root_dir,
            users_dir,
            state_path,
            state,
        })
    }

    fn root_dir(&self) -> &Path {
        &self.root_dir
    }

    fn current_user_address(&self) -> Option<&str> {
        self.state.current_user_address.as_deref()
    }

    fn context(&self) -> Option<nak3d_cli::Context> {
        Some(nak3d_cli::Context {
            rpc_url: self.rpc_url()?.to_string(),
            router_address: self.router_address()?.parse().ok()?,
        })
    }

    fn user_info(&self) -> Option<nak3d_cli::UserInfo> {
        let address = self.current_user_address()?;
        let user = self.load_user(address).ok()?;

        Some(nak3d_cli::UserInfo {
            address: user.eth_address.parse().ok()?,
            sk: user.private_key.parse().ok()?,
        })
    }

    fn current_user_name(&self) -> Option<String> {
        self.current_user_address()
            .and_then(|address| self.load_user(address).ok())
            .map(|user| user.name)
    }

    fn contract_address(&self) -> Option<&str> {
        self.state.contract_address.as_deref()
    }

    fn rpc_url(&self) -> Option<&str> {
        self.state.rpc_url.as_deref()
    }

    fn router_address(&self) -> Option<&str> {
        self.state.router_address.as_deref()
    }

    fn set_current_user(&mut self, address: String) -> Result<()> {
        self.state.current_user_address = Some(address);
        self.save_state()
    }

    fn set_router_address(&mut self, address: String) -> Result<()> {
        // Just save the router address in state; no on-chain check is performed.
        self.state.router_address = Some(address);
        self.save_state()
    }

    fn set_contract_address(&mut self, address: String) -> Result<()> {
        self.state.contract_address = Some(address);
        self.save_state()
    }

    fn set_rpc_url(&mut self, rpc_url: String) -> Result<()> {
        self.state.rpc_url = Some(rpc_url);
        self.save_state()
    }

    fn save_state(&self) -> Result<()> {
        write_json(&self.state_path, &self.state)
            .with_context(|| format!("failed to write {}", self.state_path.display()))
    }

    fn user_path(&self, address: &str) -> PathBuf {
        self.users_dir.join(format!("{address}.json"))
    }

    fn user_exists(&self, address: &str) -> bool {
        self.user_path(address).exists()
    }

    fn load_user(&self, address: &str) -> Result<UserRecord> {
        let path = self.user_path(address);
        read_json_required(&path)
            .with_context(|| format!("failed to read user file {}", path.display()))
    }

    fn save_user(&self, user: &UserRecord) -> Result<()> {
        let path = self.user_path(&user.eth_address);
        write_json(&path, user).with_context(|| format!("failed to write {}", path.display()))
    }

    fn load_current_user(&self) -> Result<UserRecord> {
        let address = self
            .current_user_address()
            .ok_or_else(|| anyhow!("no current user; run `login` first"))?;
        self.load_user(address)
    }

    fn find_users_by_name(&self, name: &str) -> Result<Vec<UserRecord>> {
        let mut users = Vec::new();

        for entry in fs::read_dir(&self.users_dir).with_context(|| {
            format!(
                "failed to read users directory at {}",
                self.users_dir.display()
            )
        })? {
            let entry = entry?;
            let path = entry.path();
            if !path.is_file() || path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }

            let user: UserRecord = read_json_required(&path)
                .with_context(|| format!("failed to parse user file {}", path.display()))?;

            if user.name.eq_ignore_ascii_case(name) {
                users.push(user);
            }
        }

        Ok(users)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let mut db = Db::load()?;
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    match cli.command {
        Command::UploadCode(args) => {
            let db = Db::load()?;
            let context = db
                .context()
                .ok_or_else(|| anyhow!("missing context (rpc url or router address)"))?;
            let user_info = db
                .user_info()
                .ok_or_else(|| anyhow!("no current user with private key; run `login` first"))?;
            nak3d_cli::deploy::upload_code(context, user_info, args.wasm_path).await
        }
        Command::CreateNewContract(args) => {
            let db = Db::load()?;
            let context = db
                .context()
                .ok_or_else(|| anyhow!("missing context (rpc url or router address)"))?;
            let user_info = db
                .user_info()
                .ok_or_else(|| anyhow!("no current user with private key; run `login` first"))?;
            nak3d_cli::deploy::create_program(context, user_info, args.code_id.parse()?, None).await
        }
        Command::Login(args) => handle_login(&mut db, args),
        Command::Set(args) => handle_set(&mut db, args).await,
        Command::ShowState => handle_show_state(&db),
        Command::GetProfiles(args) => handle_get_profiles(&db, args),
        Command::UploadHiddenContent(args) => handle_upload_hidden_content(&mut db, args),
        Command::RunModelClient(args) => handle_run_model_client(&db, args),
        Command::BuyHiddenContent(args) => handle_buy_hidden_content(&mut db, args),
    }
}

fn handle_show_state(db: &Db) -> Result<()> {
    println!("DB root: {}", db.root_dir().display());
    println!(
        "Current user: {} {}",
        db.current_user_name().unwrap_or("<no-name>".to_string()),
        db.current_user_address().unwrap_or("<not-set>")
    );
    println!("Contract: {}", db.contract_address().unwrap_or("<not-set>"));
    println!("RPC: {}", db.rpc_url().unwrap_or("<not-set>"));
    Ok(())
}

fn handle_login(db: &mut Db, args: LoginArgs) -> Result<()> {
    if looks_like_eth_address(&args.user) {
        let address = normalize_eth_address(&args.user)?;

        if db.user_exists(&address) {
            let mut user = db.load_user(&address)?;
            if let Some(name) = args.name {
                user.name = name;
            }
            if let Some(private_key) = args.private_key {
                user.private_key = private_key;
            }
            db.save_user(&user)?;
            db.set_current_user(address.clone())?;

            println!("Logged in: {} ({address})", user.name);
            println!("DB root: {}", db.root_dir().display());
            return Ok(());
        }

        let name = args
            .name
            .ok_or_else(|| anyhow!("new user requires `--name`"))?;
        let private_key = args
            .private_key
            .ok_or_else(|| anyhow!("new user requires `--private-key`"))?;

        let user = UserRecord::new(address.clone(), name, private_key);
        db.save_user(&user)?;
        db.set_current_user(address.clone())?;

        println!("New user created and logged in: {} ({address})", user.name);
        println!("DB root: {}", db.root_dir().display());
        return Ok(());
    }

    let users = db.find_users_by_name(&args.user)?;
    if users.is_empty() {
        bail!(
            "user `{}` not found; create with `login <eth-address> --name <name> --private-key <key>`",
            args.user
        );
    }

    if users.len() > 1 {
        let addresses = users
            .iter()
            .map(|user| user.eth_address.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        bail!(
            "name `{}` is ambiguous, matched multiple addresses: {addresses}",
            args.user
        );
    }

    let user = users
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("internal error: empty user list"))?;
    db.set_current_user(user.eth_address.clone())?;

    println!("Logged in: {} ({})", user.name, user.eth_address);
    println!("DB root: {}", db.root_dir().display());
    Ok(())
}

async fn handle_set(db: &mut Db, args: SetArgs) -> Result<()> {
    match args.command {
        SetCommand::RouterAddress { address } => {
            // Just validate the address format and save it; no on-chain check is performed.
            let _ =
                normalize_eth_address(&address).with_context(|| "invalid router address format")?;
            db.set_router_address(address.clone())?;
            println!("Router address saved: {address}");
            println!("DB root: {}", db.root_dir().display());
            Ok(())
        }
        SetCommand::ContractAddress {
            address: address_string,
        } => {
            let address = gsigner::Address::from_str(&address_string).unwrap();

            if let Some(rpc) = db.rpc_url() {
                println!("Check if contract exists at {address} using RPC {rpc}...");
                let provider = RootProvider::connect(rpc).await.unwrap();
                let mirror = ethexe_ethereum::mirror::MirrorQuery::new(provider, address);
                let state_hash = mirror
                    .state_hash()
                    .await
                    .expect("Looks like is not a correct mirror address");
                println!("Contract state hash: {state_hash:#x}");
            }

            db.set_contract_address(address_string)?;
            println!("Contract address saved: {address}");
            println!("DB root: {}", db.root_dir().display());

            Ok(())
        }
        SetCommand::RpcUrl { url } => {
            db.set_rpc_url(url.clone())?;
            println!("RPC URL saved: {url}");
            println!("DB root: {}", db.root_dir().display());
            Ok(())
        }
    }
}

fn handle_get_profiles(db: &Db, _args: GetProfilesArgs) -> Result<()> {
    let contract_address = required_contract_address(db)?;
    let rpc_url = required_rpc_url(db)?;

    println!("Contract: {contract_address}");
    println!("RPC: {rpc_url}");
    println!("Get profiles is a stub. Add RPC query implementation in this handler.");
    Ok(())
}

fn handle_upload_hidden_content(db: &mut Db, args: UploadHiddenContentArgs) -> Result<()> {
    let mut current_user = db.load_current_user()?;
    let contract_address = required_contract_address(db)?;
    let old_value = current_user
        .content_preproofs
        .insert(args.content_id, args.pre_proof);
    db.save_user(&current_user)?;

    println!(
        "Model: {} ({})",
        current_user.name, current_user.eth_address
    );
    println!("Contract: {contract_address}");
    println!("Upload hidden content is a stub. Contract call is not implemented.");
    if old_value.is_some() {
        println!(
            "Updated local pre-proof mapping for content_id {}",
            args.content_id
        );
    } else {
        println!(
            "Saved local pre-proof mapping for content_id {}",
            args.content_id
        );
    }
    Ok(())
}

fn handle_run_model_client(db: &Db, args: RunModelClientArgs) -> Result<()> {
    let current_user = db.load_current_user()?;
    let contract_address = required_contract_address(db)?;
    let mut iterations = 0u64;
    let total_earned: u128 = 0;

    println!(
        "Model client started for {} ({})",
        current_user.name, current_user.eth_address
    );
    println!("Contract: {contract_address}");
    println!("Waiting for content purchase requests...");

    loop {
        if let Some(max_iterations) = args.max_iterations {
            if iterations >= max_iterations {
                println!("Stopped after {iterations} iterations.");
                return Ok(());
            }
        }

        thread::sleep(Duration::from_secs(args.poll_interval_secs));
        iterations = iterations.saturating_add(1);

        // Contract polling + reply is intentionally left as stub.
        println!("[tick {iterations}] no purchase request, earned total: {total_earned}");
    }
}

fn handle_buy_hidden_content(db: &mut Db, args: BuyHiddenContentArgs) -> Result<()> {
    let mut buyer = db.load_current_user()?;
    let contract_address = required_contract_address(db)?;
    let model_address = normalize_eth_address(&args.model_address)?;

    let now = unix_time_secs()?;
    let purchase_id = buyer.purchases.last().map_or(1, |last| last.id + 1);
    let mut purchase = PurchaseRecord {
        id: purchase_id,
        model_address,
        content_id: args.content_id,
        status: PurchaseStatus::Pending,
        user_balance: 0,
        contract_balance: 0,
        model_balance: 0,
        created_at_unix_secs: now,
        updated_at_unix_secs: now,
    };

    println!("Buyer: {} ({})", buyer.name, buyer.eth_address);
    println!("Contract: {contract_address}");
    println!(
        "Purchase request sent: model={}, content_id={}",
        purchase.model_address, purchase.content_id
    );
    println!("Status: pending");

    // Request + wait + decrypt/reply workflow is intentionally left as stub.
    purchase.status = PurchaseStatus::Completed;
    purchase.updated_at_unix_secs = unix_time_secs()?;
    buyer.purchases.push(purchase.clone());
    db.save_user(&buyer)?;

    println!("Status: completed");
    println!("Final balances:");
    println!("  user: {}", purchase.user_balance);
    println!("  contract: {}", purchase.contract_balance);
    println!("  model: {}", purchase.model_balance);
    Ok(())
}

fn required_contract_address(db: &Db) -> Result<String> {
    db.contract_address()
        .map(ToOwned::to_owned)
        .ok_or_else(|| anyhow!("contract address is not set; run `set contract-address <address>`"))
}

fn required_rpc_url(db: &Db) -> Result<String> {
    db.rpc_url()
        .map(ToOwned::to_owned)
        .ok_or_else(|| anyhow!("rpc url is not set; run `set rpc-url <url>`"))
}

fn default_data_dir() -> Result<PathBuf> {
    let project_dirs = ProjectDirs::from(APP_QUALIFIER, APP_ORGANIZATION, APP_NAME)
        .ok_or_else(|| anyhow!("failed to detect default application files directory"))?;
    Ok(project_dirs.data_local_dir().to_path_buf())
}

fn looks_like_eth_address(value: &str) -> bool {
    value.trim().starts_with("0x")
}

fn normalize_eth_address(value: &str) -> Result<String> {
    let trimmed = value.trim();
    ensure!(trimmed.starts_with("0x"), "address must start with `0x`");
    ensure!(
        trimmed.len() == 42,
        "address length must be 42 chars including `0x`"
    );
    ensure!(
        trimmed[2..].chars().all(|ch| ch.is_ascii_hexdigit()),
        "address contains non-hex characters"
    );

    Ok(format!("0x{}", trimmed[2..].to_ascii_lowercase()))
}

fn unix_time_secs() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system time is before unix epoch")?
        .as_secs())
}

fn read_json_required<T>(path: &Path) -> Result<T>
where
    T: DeserializeOwned,
{
    let data =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    let parsed = serde_json::from_str(&data)
        .with_context(|| format!("failed to parse json from {}", path.display()))?;
    Ok(parsed)
}

fn read_json_or_default<T>(path: &Path) -> Result<T>
where
    T: DeserializeOwned + Default,
{
    if !path.exists() {
        return Ok(T::default());
    }

    let data =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    if data.trim().is_empty() {
        return Ok(T::default());
    }

    let parsed = serde_json::from_str(&data)
        .with_context(|| format!("failed to parse json from {}", path.display()))?;
    Ok(parsed)
}

fn write_json<T>(path: &Path, value: &T) -> Result<()>
where
    T: Serialize,
{
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }

    let data = serde_json::to_string_pretty(value)
        .with_context(|| format!("failed to serialize json for {}", path.display()))?;
    fs::write(path, data).with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}
