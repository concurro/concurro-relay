//! Request-only QuickSilver check for the synthetic TLS 1.3 handoff fixture.

use std::{io::Read, sync::Arc, time::Instant};

use anyhow::{Context as _, Result, bail, ensure};
use mpz_circuits::{AES128_KS, AES128_POST_KS, Circuit, CircuitBuilder, circuits::xor};
use mpz_common::Context;
use mpz_core::{Block, bitvec::BitVec};
use mpz_hash::sha256::Sha256;
use mpz_ot::{chou_orlandi as co, ferret, kos};
use mpz_vm_core::{
    Call, CallableExt, Execute, Vm,
    memory::{
        Array, DecodeFutureTyped, MemoryExt, Vector, ViewExt,
        binary::{Binary, U8},
        correlated::Delta,
    },
};
use mpz_zk::{Prover, ProverConfig, Verifier, VerifierConfig};
use serde::Deserialize;
use std::os::fd::AsRawFd;
use tokio::net::{TcpListener, TcpStream};

unsafe extern "C" {
    /// Run 128 malicious random base OTs as sender over a connected proof socket.
    fn handoff_mrr_send_fd(fd: i32, first: *mut u8, second: *mut u8) -> i32;
    /// Run 128 malicious random base OTs as receiver over a connected proof socket.
    fn handoff_mrr_receive_fd(fd: i32, choices: *const bool, selected: *mut u8) -> i32;
}
use tokio_util::compat::TokioAsyncReadCompatExt;

/// One exact TLS application record and its public audit claim.
#[derive(Deserialize)]
struct Input {
    /// Hash of the exact ClientHello and ServerHello pair.
    h2: String,
    /// Hash through the authenticated provider Finished message.
    h3: String,
    /// Public commitment emitted by the protected prefix circuit.
    key_commitment: String,
    /// Concurro-only AES-128 request key; zero-filled at the verifier.
    key: String,
    /// Concurro-only TLS 1.3 request IV; zero-filled at the verifier.
    iv: String,
    /// TLS record sequence after the protected KeyUpdate.
    sequence: u64,
    /// Public application bytes that the sponsor audits.
    plaintext: String,
    /// Exact record bytes that the sponsor forwards.
    record: String,
}

/// Decoded checks whose contents do not expose the secret AES key or IV.
struct Checks {
    /// Hash of the hidden key and IV with the public session transcript.
    commitment: DecodeFutureTyped<BitVec, [u8; 32]>,
    /// One public equality result per ciphertext block.
    blocks: Vec<DecodeFutureTyped<BitVec, [u8; 1]>>,
}

/// Allocate and commit public bytes identically on the prover and verifier.
fn public_bytes(vm: &mut dyn Vm<Binary>, bytes: &[u8]) -> Result<Vector<U8>> {
    let value = vm.alloc_vec::<U8>(bytes.len())?;
    vm.mark_public(value)?;
    vm.assign(value, bytes.to_vec())?;
    vm.commit(value)?;
    Ok(value)
}

/// Compare only the used AES stream bytes with a public request/ciphertext claim.
fn equal_prefix(bytes: usize) -> Arc<Circuit> {
    let mut builder = CircuitBuilder::new();
    let stream: Vec<_> = (0..128).map(|_| builder.add_input()).collect();
    let expected: Vec<_> = (0..bytes * 8).map(|_| builder.add_input()).collect();
    let mut equal = None;
    for i in 0..bytes * 8 {
        let difference = builder.add_xor_gate(stream[i], expected[i]);
        let same = builder.add_inv_gate(difference);
        equal = Some(match equal {
            Some(previous) => builder.add_and_gate(previous, same),
            None => same,
        });
    }
    let equal = equal.expect("record contains an inner content type");
    for _ in 0..8 {
        let bit = builder.add_id_gate(equal);
        builder.add_output(bit);
    }
    Arc::new(builder.build().expect("valid equality circuit"))
}

/// Bind the handoff key commitment and all application ciphertext bytes to this record.
fn relation(vm: &mut dyn Vm<Binary>, prover: bool, input: &Input) -> Result<Checks> {
    let h2 = hex::decode(&input.h2)?;
    let h3 = hex::decode(&input.h3)?;
    let key = hex::decode(&input.key)?;
    let iv = hex::decode(&input.iv)?;
    let plaintext = hex::decode(&input.plaintext)?;
    let record = hex::decode(&input.record)?;
    ensure!(h2.len() == 32 && h3.len() == 32 && key.len() == 16 && iv.len() == 12);
    ensure!(record.len() == plaintext.len() + 22);
    ensure!(record[..3] == [23, 3, 3]);
    ensure!(usize::from(u16::from_be_bytes([record[3], record[4]])) == record.len() - 5);
    let mut inner = plaintext;
    inner.push(23);
    let ciphertext = &record[5..5 + inner.len()];
    let expected_stream: Vec<u8> = inner.iter().zip(ciphertext).map(|(&p, &c)| p ^ c).collect();

    let key_ref: Array<U8, 16> = vm.alloc()?;
    let iv_ref: Array<U8, 12> = vm.alloc()?;
    if prover {
        vm.mark_private(key_ref)?;
        vm.mark_private(iv_ref)?;
        vm.assign(key_ref, key.try_into().expect("validated key length"))?;
        vm.assign(iv_ref, iv.try_into().expect("validated IV length"))?;
    } else {
        vm.mark_blind(key_ref)?;
        vm.mark_blind(iv_ref)?;
    }
    vm.commit(key_ref)?;
    vm.commit(iv_ref)?;

    let mut hash = Sha256::new();
    let domain = public_bytes(vm, b"Concurro/Handoff/v1/request-key")?;
    let h2_ref = public_bytes(vm, &h2)?;
    let h3_ref = public_bytes(vm, &h3)?;
    hash.update(&domain);
    hash.update(&h2_ref);
    hash.update(&h3_ref);
    hash.update(&Vector::from(key_ref));
    hash.update(&Vector::from(iv_ref));
    let commitment_ref = hash.finalize(vm)?;
    let commitment = vm.decode(commitment_ref)?;

    let mut mask = [0u8; 12];
    mask[4..].copy_from_slice(&input.sequence.to_be_bytes());
    let mask_ref = public_bytes(vm, &mask)?;
    let nonce: Array<U8, 12> = vm.call(
        Call::builder(Arc::new(xor(96)))
            .arg(iv_ref)
            .arg(mask_ref)
            .build()?,
    )?;
    let nonce = Vector::from(nonce);
    let prefix = nonce.get(0..4).expect("nonce first four bytes");
    let suffix = nonce.get(4..12).expect("nonce final eight bytes");
    let schedule: Array<U8, 176> =
        vm.call(Call::builder(AES128_KS.clone()).arg(key_ref).build()?)?;
    let mut blocks = Vec::new();
    let full_block_equality = equal_prefix(16);
    for (index, chunk) in expected_stream.chunks(16).enumerate() {
        let counter = public_bytes(vm, &u32::try_from(index + 2)?.to_be_bytes())?;
        let stream: Array<U8, 16> = vm.call(
            Call::builder(AES128_POST_KS.clone())
                .arg(schedule)
                .arg(prefix)
                .arg(suffix)
                .arg(counter)
                .build()?,
        )?;
        let expected = public_bytes(vm, chunk)?;
        let equality = if chunk.len() == 16 {
            full_block_equality.clone()
        } else {
            equal_prefix(chunk.len())
        };
        let valid: Array<U8, 1> =
            vm.call(Call::builder(equality).arg(stream).arg(expected).build()?)?;
        blocks.push(vm.decode(valid)?);
    }
    Ok(Checks { commitment, blocks })
}

/// Resolve authenticated outputs and refuse any missing byte or key binding.
fn check(mut outputs: Checks, input: &Input) -> Result<()> {
    let expected = hex::decode(&input.key_commitment)?;
    ensure!(expected.len() == 32);
    ensure!(
        outputs
            .commitment
            .try_recv()?
            .context("commitment was not decoded")?
            .as_slice()
            == expected
    );
    for block in &mut outputs.blocks {
        ensure!(block.try_recv()?.context("block was not decoded")? == [0xff]);
    }
    Ok(())
}

/// Run Concurro's proof with fresh malicious MRR, KOS and Ferret OT state.
async fn run_prover(stream: TcpStream, input: &Input) -> Result<()> {
    let stream = stream.into_std()?;
    stream.set_nonblocking(false)?;
    let mut first = [[0u8; 16]; 128];
    let mut second = [[0u8; 16]; 128];
    let status = unsafe {
        handoff_mrr_send_fd(
            stream.as_raw_fd(),
            first.as_mut_ptr().cast(),
            second.as_mut_ptr().cast(),
        )
    };
    ensure!(status == 0, "request proof MRR sender failed");
    stream.set_nonblocking(true)?;
    let stream = TcpStream::from_std(stream)?;
    let seeds = std::array::from_fn(|i| [Block::new(first[i]), Block::new(second[i])]);
    let kos =
        kos::Receiver::<co::Sender>::new_with_base_seeds(kos::ReceiverConfig::default(), seeds);
    let mut rng = rand::rng();
    let ferret = ferret::Receiver::new(
        ferret::FerretConfig::default(),
        Block::random(&mut rng),
        kos,
    );
    let mut vm = Prover::new(ProverConfig::default(), ferret);
    let checks = relation(&mut vm, true, input)?;
    let mut context = Context::new_single_threaded(stream.compat());
    vm.execute_all(&mut context).await?;
    check(checks, input)
}

/// Run the sponsor's verifier using the independently supplied prefix commitment.
async fn run_verifier(stream: TcpStream, input: &Input) -> Result<()> {
    let mut rng = rand::rng();
    let delta = Delta::random(&mut rng);
    let stream = stream.into_std()?;
    stream.set_nonblocking(false)?;
    let delta_block = delta.into_inner();
    let choices: [bool; 128] =
        std::array::from_fn(|i| delta_block.as_bytes()[i / 8] & (1 << (i % 8)) != 0);
    let mut selected = [[0u8; 16]; 128];
    let status = unsafe {
        handoff_mrr_receive_fd(
            stream.as_raw_fd(),
            choices.as_ptr(),
            selected.as_mut_ptr().cast(),
        )
    };
    ensure!(status == 0, "request proof MRR receiver failed");
    stream.set_nonblocking(true)?;
    let stream = TcpStream::from_std(stream)?;
    let seeds = std::array::from_fn(|i| Block::new(selected[i]));
    let kos = kos::Sender::<co::Receiver>::new_with_base_seeds(
        kos::SenderConfig::default(),
        delta_block,
        seeds,
    );
    let ferret = ferret::Sender::new(
        ferret::FerretConfig::default(),
        Block::random(&mut rng),
        kos,
    );
    let mut vm = Verifier::new(VerifierConfig::default(), delta, ferret);
    let checks = relation(&mut vm, false, input)?;
    let mut context = Context::new_single_threaded(stream.compat());
    vm.execute_all(&mut context).await?;
    check(checks, input)
}

/// Read a single JSON input and run one request-only proof subprocess.
#[tokio::main]
async fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let role = args.next().context("missing prover/verifier role")?;
    let port = args.next();
    let mut json = String::new();
    std::io::stdin().read_to_string(&mut json)?;
    let input: Input = serde_json::from_str(&json)?;
    let started = Instant::now();
    match role.as_str() {
        "verifier" => {
            ensure!(port.is_none());
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            eprintln!("REQUEST_READY {}", listener.local_addr()?.port());
            let (stream, _) = listener.accept().await?;
            run_verifier(stream, &input).await?;
        }
        "prover" => {
            let port = port.context("missing verifier port")?;
            let stream = TcpStream::connect(format!("127.0.0.1:{port}")).await?;
            run_prover(stream, &input).await?;
        }
        _ => bail!("unknown role"),
    }
    eprintln!(
        "REQUEST_OK {{\"role\":\"{role}\",\"elapsed_ms\":{}}}",
        started.elapsed().as_millis()
    );
    Ok(())
}
