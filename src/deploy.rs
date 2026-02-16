use crate::{Context, UserInfo};
use anyhow::{Context as _, Result};
use gear_core::ids::prelude::CodeIdExt as _;
use gprimitives::{CodeId, H256};
use gsigner::prelude::Secp256k1;
use std::{fs, path::PathBuf};

pub async fn upload_code(ctx: Context, user: UserInfo, wasm_path: PathBuf) -> Result<()> {
    log::info!(
        "Uploading code from path: {wasm_path:?}, user: {}, ctx: {ctx:?}",
        user.address
    );

    let signer = gsigner::Signer::<Secp256k1>::memory();
    let _ = signer.import(user.sk).unwrap();
    let ethereum =
        ethexe_ethereum::Ethereum::new(&ctx.rpc_url, ctx.router_address, signer, user.address)
            .await?;

    let code = fs::read(wasm_path.clone()).with_context(|| "failed to read wasm from file")?;
    let code_id = CodeId::generate(&code);
    let code_size_bytes = code.len();
    let code_size_kib = code_size_bytes as f64 / 1024.0;

    log::info!("Uploading {} to Ethereum", wasm_path.display());
    log::info!("  Code id:   {code_id} (blake2b256)");
    log::info!("  Code size: {code_size_bytes} bytes ({code_size_kib:.2} KiB)",);

    let (_, code_id) = ethereum.router().request_code_validation(&code).await?;
    log::info!("Code validation request sent, code id: {code_id}");

    let res = ethereum.router().wait_for_code_validation(code_id).await?;
    log::info!("Code validation result: {res:?}");

    Ok(())
}

pub async fn create_program(
    ctx: Context,
    user: UserInfo,
    code_id: CodeId,
    executable_balance: Option<u128>,
) -> Result<()> {
    log::info!(
        "Creating program with code id: {code_id}, user: {}, ctx: {ctx:?}",
        user.address
    );

    let signer = gsigner::Signer::<Secp256k1>::memory();
    let _ = signer.import(user.sk).unwrap();
    let ethereum =
        ethexe_ethereum::Ethereum::new(&ctx.rpc_url, ctx.router_address, signer, user.address)
            .await?;

    let (_, program_id) = ethereum
        .router()
        .create_program(code_id, H256::random(), None)
        .await?;
    log::info!("Program created with id: {program_id}");

    let value = executable_balance.unwrap_or(10_000_000_000_000u128);
    log::info!("Approve balance for {program_id} {value} ...");
    ethereum
        .wrapped_vara()
        .approve(program_id, value)
        .await
        .unwrap();
    log::info!("Wvara approved");

    log::info!("Top up executable balance for {program_id} with {value} ...");
    ethereum
        .mirror(program_id)
        .executable_balance_top_up(value)
        .await
        .unwrap();
    log::info!("Executable balance topped up");

    let init_message = onlyhack_client::io::Create::encode_params();
    log::info!(
        "Sending init message {} to {program_id} ...",
        String::from_utf8_lossy(&init_message)
    );
    let (_, message_id) = ethereum
        .mirror(program_id)
        .send_message(init_message, 0)
        .await
        .unwrap();
    log::info!("Init message {message_id} sent, wait for reply ...");
    let reply = ethereum
        .mirror(program_id)
        .wait_for_reply(message_id)
        .await?;
    log::info!("Init message reply: {reply:?}");

    if reply.code.is_success() {
        log::info!("Program {program_id} created successfully");
        Ok(())
    } else {
        log::error!("Program {program_id} creation failed");
        Err(anyhow::anyhow!("Program creation failed"))
    }
}
