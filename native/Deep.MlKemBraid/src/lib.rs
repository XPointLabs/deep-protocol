#![deny(unsafe_op_in_unsafe_fn)]

use libcrux_ml_kem::mlkem768::incremental;
use std::collections::HashMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use zeroize::{Zeroize, Zeroizing};

const KEYGEN_RANDOM_SIZE: usize = 64;
const DK_SIZE: usize = 2400;
const EK_SEED_SIZE: usize = 32;
const EK_HASH_SIZE: usize = 32;
const EK_VECTOR_SIZE: usize = 1152;
const ENCAPS_RANDOM_SIZE: usize = 32;
const CT1_SIZE: usize = 960;
const CT2_SIZE: usize = 128;
const SHARED_SECRET_SIZE: usize = 32;
const STATE_SIZE: usize = 2080;
const MAX_ACTIVE_STATES: usize = 1024;

#[repr(i32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Status {
    Ok = 0,
    InvalidArgument = 1,
    InvalidLength = 2,
    Overlap = 3,
    InvalidHandle = 4,
    InvalidPublicKey = 5,
    EntropyFailure = 6,
    InternalError = 7,
}

impl Status {
    fn from_code(code: i32) -> Self {
        match code {
            0 => Self::Ok,
            1 => Self::InvalidArgument,
            2 => Self::InvalidLength,
            3 => Self::Overlap,
            4 => Self::InvalidHandle,
            5 => Self::InvalidPublicKey,
            6 => Self::EntropyFailure,
            _ => Self::InternalError,
        }
    }
}

struct EncapsulationState {
    serialized: Box<[u8; STATE_SIZE]>,
    shared_secret: [u8; SHARED_SECRET_SIZE],
    ek_seed: [u8; EK_SEED_SIZE],
    ek_hash: [u8; EK_HASH_SIZE],
}

impl Drop for EncapsulationState {
    fn drop(&mut self) {
        self.serialized.as_mut().zeroize();
        self.shared_secret.zeroize();
        self.ek_seed.zeroize();
        self.ek_hash.zeroize();
    }
}

static STATES: OnceLock<Mutex<HashMap<u64, EncapsulationState>>> = OnceLock::new();
static NEXT_HANDLE: AtomicU64 = AtomicU64::new(1);

fn states() -> &'static Mutex<HashMap<u64, EncapsulationState>> {
    STATES.get_or_init(|| Mutex::new(HashMap::new()))
}

fn has_state_capacity(active_state_count: usize) -> bool {
    active_state_count < MAX_ACTIVE_STATES
}

fn insert_state(state: EncapsulationState) -> Result<u64, Status> {
    let mut states = states().lock().map_err(|_| Status::InternalError)?;
    if !has_state_capacity(states.len()) {
        return Err(Status::InternalError);
    }
    for _ in 0..u16::MAX {
        let handle = NEXT_HANDLE.fetch_add(1, Ordering::Relaxed);
        if handle != 0 && !states.contains_key(&handle) {
            states.insert(handle, state);
            return Ok(handle);
        }
    }
    Err(Status::InternalError)
}

fn take_state(handle: u64) -> Result<EncapsulationState, Status> {
    if handle == 0 {
        return Err(Status::InvalidHandle);
    }
    states()
        .lock()
        .map_err(|_| Status::InternalError)?
        .remove(&handle)
        .ok_or(Status::InvalidHandle)
}

#[derive(Clone, Copy)]
struct Region {
    start: usize,
    end: usize,
}

impl Region {
    fn new(ptr: *const u8, len: usize) -> Result<Self, Status> {
        if ptr.is_null() {
            return Err(Status::InvalidArgument);
        }
        let start = ptr as usize;
        let end = start.checked_add(len).ok_or(Status::InvalidArgument)?;
        Ok(Self { start, end })
    }

    fn overlaps(self, other: Self) -> bool {
        self.start < other.end && other.start < self.end
    }
}

fn reject_overlap(regions: &[Region]) -> Result<(), Status> {
    for (index, left) in regions.iter().enumerate() {
        if regions[index + 1..]
            .iter()
            .any(|right| left.overlaps(*right))
        {
            return Err(Status::Overlap);
        }
    }
    Ok(())
}

unsafe fn zero_exact(ptr: *mut u8, len: usize, expected: usize) {
    if !ptr.is_null() && len == expected {
        unsafe { ptr::write_bytes(ptr, 0, len) };
    }
}

unsafe fn zero_handle(ptr: *mut u64) {
    if !ptr.is_null() {
        unsafe { ptr::write_unaligned(ptr, 0) };
    }
}

fn exact_len(actual: usize, expected: usize) -> Result<(), Status> {
    if actual == expected {
        Ok(())
    } else {
        Err(Status::InvalidLength)
    }
}

unsafe fn read_array<const N: usize>(source: *const u8) -> [u8; N] {
    let mut value = [0u8; N];
    unsafe { ptr::copy_nonoverlapping(source, value.as_mut_ptr(), N) };
    value
}

unsafe fn write_array<const N: usize>(destination: *mut u8, value: &[u8; N]) {
    unsafe { ptr::copy_nonoverlapping(value.as_ptr(), destination, N) };
}

fn fixed_equals(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (&a, &b) in left.iter().zip(right) {
        difference |= a ^ b;
    }
    difference == 0
}

fn ffi(operation: impl FnOnce() -> Result<(), Status>) -> i32 {
    match catch_unwind(AssertUnwindSafe(operation)) {
        Ok(Ok(())) => Status::Ok as i32,
        Ok(Err(status)) => status as i32,
        Err(_) => Status::InternalError as i32,
    }
}

#[no_mangle]
pub extern "C" fn deep_mlkem_braid_v1_keygen_random_size() -> usize {
    KEYGEN_RANDOM_SIZE
}
#[no_mangle]
pub extern "C" fn deep_mlkem_braid_v1_decapsulation_key_size() -> usize {
    DK_SIZE
}
#[no_mangle]
pub extern "C" fn deep_mlkem_braid_v1_encapsulation_key_seed_size() -> usize {
    EK_SEED_SIZE
}
#[no_mangle]
pub extern "C" fn deep_mlkem_braid_v1_encapsulation_key_hash_size() -> usize {
    EK_HASH_SIZE
}
#[no_mangle]
pub extern "C" fn deep_mlkem_braid_v1_encapsulation_key_vector_size() -> usize {
    EK_VECTOR_SIZE
}
#[no_mangle]
pub extern "C" fn deep_mlkem_braid_v1_encapsulation_random_size() -> usize {
    ENCAPS_RANDOM_SIZE
}
#[no_mangle]
pub extern "C" fn deep_mlkem_braid_v1_ciphertext1_size() -> usize {
    CT1_SIZE
}
#[no_mangle]
pub extern "C" fn deep_mlkem_braid_v1_ciphertext2_size() -> usize {
    CT2_SIZE
}
#[no_mangle]
pub extern "C" fn deep_mlkem_braid_v1_shared_secret_size() -> usize {
    SHARED_SECRET_SIZE
}

#[no_mangle]
pub unsafe extern "C" fn deep_mlkem_braid_v1_keypair_from_random(
    random64: *const u8,
    random64_len: usize,
    dk2400: *mut u8,
    dk2400_len: usize,
    ek_vector1152: *mut u8,
    ek_vector1152_len: usize,
    ek_seed32: *mut u8,
    ek_seed32_len: usize,
    ek_hash32: *mut u8,
    ek_hash32_len: usize,
) -> i32 {
    ffi(|| unsafe {
        exact_len(random64_len, KEYGEN_RANDOM_SIZE)?;
        exact_len(dk2400_len, DK_SIZE)?;
        exact_len(ek_vector1152_len, EK_VECTOR_SIZE)?;
        exact_len(ek_seed32_len, EK_SEED_SIZE)?;
        exact_len(ek_hash32_len, EK_HASH_SIZE)?;
        let regions = [
            Region::new(random64, KEYGEN_RANDOM_SIZE)?,
            Region::new(dk2400, DK_SIZE)?,
            Region::new(ek_vector1152, EK_VECTOR_SIZE)?,
            Region::new(ek_seed32, EK_SEED_SIZE)?,
            Region::new(ek_hash32, EK_HASH_SIZE)?,
        ];
        reject_overlap(&regions)?;
        zero_exact(dk2400, dk2400_len, DK_SIZE);
        zero_exact(ek_vector1152, ek_vector1152_len, EK_VECTOR_SIZE);
        zero_exact(ek_seed32, ek_seed32_len, EK_SEED_SIZE);
        zero_exact(ek_hash32, ek_hash32_len, EK_HASH_SIZE);

        let randomness = Zeroizing::new(read_array::<KEYGEN_RANDOM_SIZE>(random64));
        let key_pair = incremental::KeyPairCompressedBytes::from_seed(*randomness);
        let seed = <[u8; EK_SEED_SIZE]>::try_from(&key_pair.pk1()[..EK_SEED_SIZE])
            .map_err(|_| Status::InternalError)?;
        let hash = <[u8; EK_HASH_SIZE]>::try_from(&key_pair.pk1()[EK_SEED_SIZE..])
            .map_err(|_| Status::InternalError)?;
        let vector = *key_pair.pk2();
        let private_key = Zeroizing::new(key_pair.to_bytes());

        write_array(dk2400, &private_key);
        write_array(ek_vector1152, &vector);
        write_array(ek_seed32, &seed);
        write_array(ek_hash32, &hash);
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn deep_mlkem_braid_v1_keypair_generate(
    dk2400: *mut u8,
    dk2400_len: usize,
    ek_vector1152: *mut u8,
    ek_vector1152_len: usize,
    ek_seed32: *mut u8,
    ek_seed32_len: usize,
    ek_hash32: *mut u8,
    ek_hash32_len: usize,
) -> i32 {
    ffi(|| {
        let mut randomness = Zeroizing::new([0u8; KEYGEN_RANDOM_SIZE]);
        getrandom::fill(randomness.as_mut()).map_err(|_| Status::EntropyFailure)?;
        let code = unsafe {
            deep_mlkem_braid_v1_keypair_from_random(
                randomness.as_ptr(),
                KEYGEN_RANDOM_SIZE,
                dk2400,
                dk2400_len,
                ek_vector1152,
                ek_vector1152_len,
                ek_seed32,
                ek_seed32_len,
                ek_hash32,
                ek_hash32_len,
            )
        };
        let status = Status::from_code(code);
        if status == Status::Ok {
            Ok(())
        } else {
            Err(status)
        }
    })
}

unsafe fn encaps1_from_random_impl(
    ek_seed32: *const u8,
    ek_seed32_len: usize,
    ek_hash32: *const u8,
    ek_hash32_len: usize,
    random32: *const u8,
    random32_len: usize,
    ct1_960: *mut u8,
    ct1_960_len: usize,
    owned_state: *mut u64,
) -> Result<(), Status> {
    exact_len(ek_seed32_len, EK_SEED_SIZE)?;
    exact_len(ek_hash32_len, EK_HASH_SIZE)?;
    exact_len(random32_len, ENCAPS_RANDOM_SIZE)?;
    exact_len(ct1_960_len, CT1_SIZE)?;
    let regions = [
        Region::new(ek_seed32, EK_SEED_SIZE)?,
        Region::new(ek_hash32, EK_HASH_SIZE)?,
        Region::new(random32, ENCAPS_RANDOM_SIZE)?,
        Region::new(ct1_960, CT1_SIZE)?,
        Region::new(owned_state.cast::<u8>(), size_of::<u64>())?,
    ];
    reject_overlap(&regions)?;
    unsafe {
        zero_exact(ct1_960, ct1_960_len, CT1_SIZE);
        zero_handle(owned_state);
    }

    let seed = unsafe { read_array::<EK_SEED_SIZE>(ek_seed32) };
    let hash = unsafe { read_array::<EK_HASH_SIZE>(ek_hash32) };
    let randomness = Zeroizing::new(unsafe { read_array::<ENCAPS_RANDOM_SIZE>(random32) });
    let mut serialized = Box::new([0u8; STATE_SIZE]);
    let mut shared_secret = [0u8; SHARED_SECRET_SIZE];
    let mut pk1 = [0u8; EK_SEED_SIZE + EK_HASH_SIZE];
    pk1[..EK_SEED_SIZE].copy_from_slice(&seed);
    pk1[EK_SEED_SIZE..].copy_from_slice(&hash);

    let ct1 = incremental::encapsulate1(&pk1, *randomness, serialized.as_mut(), &mut shared_secret)
        .map_err(|_| Status::InvalidArgument)?;
    let state = EncapsulationState {
        serialized,
        shared_secret,
        ek_seed: seed,
        ek_hash: hash,
    };
    let handle = insert_state(state)?;
    unsafe {
        write_array(ct1_960, &ct1.value);
        ptr::write_unaligned(owned_state, handle);
    }
    Ok(())
}

#[no_mangle]
pub unsafe extern "C" fn deep_mlkem_braid_v1_encaps1_from_random(
    ek_seed32: *const u8,
    ek_seed32_len: usize,
    ek_hash32: *const u8,
    ek_hash32_len: usize,
    random32: *const u8,
    random32_len: usize,
    ct1_960: *mut u8,
    ct1_960_len: usize,
    owned_state: *mut u64,
) -> i32 {
    ffi(|| unsafe {
        encaps1_from_random_impl(
            ek_seed32,
            ek_seed32_len,
            ek_hash32,
            ek_hash32_len,
            random32,
            random32_len,
            ct1_960,
            ct1_960_len,
            owned_state,
        )
    })
}

#[no_mangle]
pub unsafe extern "C" fn deep_mlkem_braid_v1_encaps1_generate(
    ek_seed32: *const u8,
    ek_seed32_len: usize,
    ek_hash32: *const u8,
    ek_hash32_len: usize,
    ct1_960: *mut u8,
    ct1_960_len: usize,
    owned_state: *mut u64,
) -> i32 {
    ffi(|| {
        let mut randomness = Zeroizing::new([0u8; ENCAPS_RANDOM_SIZE]);
        getrandom::fill(randomness.as_mut()).map_err(|_| Status::EntropyFailure)?;
        unsafe {
            encaps1_from_random_impl(
                ek_seed32,
                ek_seed32_len,
                ek_hash32,
                ek_hash32_len,
                randomness.as_ptr(),
                ENCAPS_RANDOM_SIZE,
                ct1_960,
                ct1_960_len,
                owned_state,
            )
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn deep_mlkem_braid_v1_encaps2(
    owned_state: u64,
    ek_seed32: *const u8,
    ek_seed32_len: usize,
    ek_vector1152: *const u8,
    ek_vector1152_len: usize,
    ct2_128: *mut u8,
    ct2_128_len: usize,
    shared_secret32: *mut u8,
    shared_secret32_len: usize,
) -> i32 {
    ffi(|| unsafe {
        exact_len(ek_seed32_len, EK_SEED_SIZE)?;
        exact_len(ek_vector1152_len, EK_VECTOR_SIZE)?;
        exact_len(ct2_128_len, CT2_SIZE)?;
        exact_len(shared_secret32_len, SHARED_SECRET_SIZE)?;
        let regions = [
            Region::new(ek_seed32, EK_SEED_SIZE)?,
            Region::new(ek_vector1152, EK_VECTOR_SIZE)?,
            Region::new(ct2_128, CT2_SIZE)?,
            Region::new(shared_secret32, SHARED_SECRET_SIZE)?,
        ];
        reject_overlap(&regions)?;
        zero_exact(ct2_128, ct2_128_len, CT2_SIZE);
        zero_exact(shared_secret32, shared_secret32_len, SHARED_SECRET_SIZE);
        let seed = read_array::<EK_SEED_SIZE>(ek_seed32);
        let vector = read_array::<EK_VECTOR_SIZE>(ek_vector1152);

        let state = take_state(owned_state)?;
        if !fixed_equals(&seed, &state.ek_seed) {
            return Err(Status::InvalidPublicKey);
        }
        let mut pk1 = [0u8; EK_SEED_SIZE + EK_HASH_SIZE];
        pk1[..EK_SEED_SIZE].copy_from_slice(&seed);
        pk1[EK_SEED_SIZE..].copy_from_slice(&state.ek_hash);
        incremental::validate_pk_bytes(&pk1, &vector).map_err(|_| Status::InvalidPublicKey)?;
        let ct2 = incremental::encapsulate2(&state.serialized, &vector);
        write_array(ct2_128, &ct2.value);
        write_array(shared_secret32, &state.shared_secret);
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn deep_mlkem_braid_v1_decapsulate(
    dk2400: *const u8,
    dk2400_len: usize,
    ct1_960: *const u8,
    ct1_960_len: usize,
    ct2_128: *const u8,
    ct2_128_len: usize,
    shared_secret32: *mut u8,
    shared_secret32_len: usize,
) -> i32 {
    ffi(|| unsafe {
        exact_len(dk2400_len, DK_SIZE)?;
        exact_len(ct1_960_len, CT1_SIZE)?;
        exact_len(ct2_128_len, CT2_SIZE)?;
        exact_len(shared_secret32_len, SHARED_SECRET_SIZE)?;
        let regions = [
            Region::new(dk2400, DK_SIZE)?,
            Region::new(ct1_960, CT1_SIZE)?,
            Region::new(ct2_128, CT2_SIZE)?,
            Region::new(shared_secret32, SHARED_SECRET_SIZE)?,
        ];
        reject_overlap(&regions)?;
        zero_exact(shared_secret32, shared_secret32_len, SHARED_SECRET_SIZE);
        let private_key = Zeroizing::new(read_array::<DK_SIZE>(dk2400));
        let ct1 = incremental::Ciphertext1 {
            value: read_array::<CT1_SIZE>(ct1_960),
        };
        let ct2 = incremental::Ciphertext2 {
            value: read_array::<CT2_SIZE>(ct2_128),
        };
        let shared_secret = Zeroizing::new(
            incremental::decapsulate_compressed_key(&private_key, &ct1, &ct2).into(),
        );
        write_array(shared_secret32, &shared_secret);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn deep_mlkem_braid_v1_state_free(owned_state: u64) -> i32 {
    ffi(|| {
        drop(take_state(owned_state)?);
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn deep_mlkem_braid_v1_zero(buffer: *mut u8, length: usize) -> i32 {
    ffi(|| {
        if buffer.is_null() {
            return Err(Status::InvalidArgument);
        }
        if length > isize::MAX as usize {
            return Err(Status::InvalidLength);
        }
        if length == 0 {
            return Ok(());
        }
        unsafe { ptr::write_volatile(buffer, 0) };
        for index in 1..length {
            unsafe { ptr::write_volatile(buffer.add(index), 0) };
        }
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use libcrux_ml_kem::mlkem768::{self, MlKem768Ciphertext, MlKem768PrivateKey};

    fn deterministic_material() -> ([u8; 64], [u8; 32]) {
        let mut keygen = [0u8; 64];
        let mut encaps = [0u8; 32];
        for (index, value) in keygen.iter_mut().enumerate() {
            *value = index as u8;
        }
        for (index, value) in encaps.iter_mut().enumerate() {
            *value = 0xa0 ^ index as u8;
        }
        (keygen, encaps)
    }

    #[test]
    fn active_state_capacity_has_an_exact_fail_closed_boundary() {
        assert!(has_state_capacity(0));
        assert!(has_state_capacity(MAX_ACTIVE_STATES - 1));
        assert!(!has_state_capacity(MAX_ACTIVE_STATES));
        assert!(!has_state_capacity(MAX_ACTIVE_STATES + 1));
    }

    #[test]
    fn incremental_is_byte_identical_to_standard_mlkem() {
        let (keygen_random, encaps_random) = deterministic_material();
        let standard_key_pair = mlkem768::generate_key_pair(keygen_random);
        let incremental_key_pair = incremental::KeyPairCompressedBytes::from_seed(keygen_random);
        assert_eq!(standard_key_pair.sk(), incremental_key_pair.sk());
        let mut rebuilt_public = [0u8; 1184];
        rebuilt_public[..1152].copy_from_slice(incremental_key_pair.pk2());
        rebuilt_public[1152..].copy_from_slice(&incremental_key_pair.pk1()[..32]);
        assert_eq!(standard_key_pair.pk(), &rebuilt_public);

        let mut state = [0u8; STATE_SIZE];
        let mut incremental_secret = [0u8; 32];
        let ct1 = incremental::encapsulate1(
            incremental_key_pair.pk1(),
            encaps_random,
            &mut state,
            &mut incremental_secret,
        )
        .expect("valid exact header");
        let ct2 = incremental::encapsulate2(&state, incremental_key_pair.pk2());
        let (standard_ciphertext, standard_secret) =
            mlkem768::encapsulate(standard_key_pair.public_key(), encaps_random);
        let mut combined = [0u8; 1088];
        combined[..CT1_SIZE].copy_from_slice(&ct1.value);
        combined[CT1_SIZE..].copy_from_slice(&ct2.value);
        assert_eq!(standard_ciphertext.as_slice(), &combined);
        assert_eq!(standard_secret.as_slice(), &incremental_secret);

        let private_key = MlKem768PrivateKey::from(*incremental_key_pair.sk());
        let ciphertext = MlKem768Ciphertext::from(combined);
        assert_eq!(
            mlkem768::decapsulate(&private_key, &ciphertext).as_slice(),
            &incremental_secret
        );
        state.zeroize();
        incremental_secret.zeroize();
    }

    #[test]
    fn ffi_handle_is_single_consumer_and_wrong_seed_fails_closed() {
        let (keygen_random, encaps_random) = deterministic_material();
        let mut dk = [0u8; DK_SIZE];
        let mut vector = [0u8; EK_VECTOR_SIZE];
        let mut seed = [0u8; EK_SEED_SIZE];
        let mut hash = [0u8; EK_HASH_SIZE];
        let status = unsafe {
            deep_mlkem_braid_v1_keypair_from_random(
                keygen_random.as_ptr(),
                keygen_random.len(),
                dk.as_mut_ptr(),
                dk.len(),
                vector.as_mut_ptr(),
                vector.len(),
                seed.as_mut_ptr(),
                seed.len(),
                hash.as_mut_ptr(),
                hash.len(),
            )
        };
        assert_eq!(status, Status::Ok as i32);

        let mut ct1 = [0u8; CT1_SIZE];
        let mut handle = 0;
        let status = unsafe {
            deep_mlkem_braid_v1_encaps1_from_random(
                seed.as_ptr(),
                seed.len(),
                hash.as_ptr(),
                hash.len(),
                encaps_random.as_ptr(),
                encaps_random.len(),
                ct1.as_mut_ptr(),
                ct1.len(),
                &mut handle,
            )
        };
        assert_eq!(status, Status::Ok as i32);
        assert_ne!(handle, 0);

        let mut wrong_seed = seed;
        wrong_seed[0] ^= 1;
        let mut ct2 = [0x55u8; CT2_SIZE];
        let mut secret = [0x55u8; SHARED_SECRET_SIZE];
        let status = unsafe {
            deep_mlkem_braid_v1_encaps2(
                handle,
                wrong_seed.as_ptr(),
                wrong_seed.len(),
                vector.as_ptr(),
                vector.len(),
                ct2.as_mut_ptr(),
                ct2.len(),
                secret.as_mut_ptr(),
                secret.len(),
            )
        };
        assert_eq!(status, Status::InvalidPublicKey as i32);
        assert_eq!(ct2, [0u8; CT2_SIZE]);
        assert_eq!(secret, [0u8; SHARED_SECRET_SIZE]);
        assert_eq!(
            deep_mlkem_braid_v1_state_free(handle),
            Status::InvalidHandle as i32
        );

        let mut second_ct1 = [0u8; CT1_SIZE];
        let mut second_handle = 0;
        assert_eq!(
            unsafe {
                deep_mlkem_braid_v1_encaps1_from_random(
                    seed.as_ptr(),
                    seed.len(),
                    hash.as_ptr(),
                    hash.len(),
                    encaps_random.as_ptr(),
                    encaps_random.len(),
                    second_ct1.as_mut_ptr(),
                    second_ct1.len(),
                    &mut second_handle,
                )
            },
            Status::Ok as i32
        );
        let mut wrong_vector = vector;
        wrong_vector[0] ^= 1;
        ct2.fill(0x55);
        secret.fill(0x55);
        assert_eq!(
            unsafe {
                deep_mlkem_braid_v1_encaps2(
                    second_handle,
                    seed.as_ptr(),
                    seed.len(),
                    wrong_vector.as_ptr(),
                    wrong_vector.len(),
                    ct2.as_mut_ptr(),
                    ct2.len(),
                    secret.as_mut_ptr(),
                    secret.len(),
                )
            },
            Status::InvalidPublicKey as i32
        );
        assert_eq!(ct2, [0u8; CT2_SIZE]);
        assert_eq!(secret, [0u8; SHARED_SECRET_SIZE]);
        assert_eq!(
            deep_mlkem_braid_v1_state_free(second_handle),
            Status::InvalidHandle as i32
        );
    }

    #[test]
    fn ffi_roundtrip_and_replay_rejection() {
        let (keygen_random, encaps_random) = deterministic_material();
        let mut dk = [0u8; DK_SIZE];
        let mut vector = [0u8; EK_VECTOR_SIZE];
        let mut seed = [0u8; EK_SEED_SIZE];
        let mut hash = [0u8; EK_HASH_SIZE];
        assert_eq!(
            unsafe {
                deep_mlkem_braid_v1_keypair_from_random(
                    keygen_random.as_ptr(),
                    keygen_random.len(),
                    dk.as_mut_ptr(),
                    dk.len(),
                    vector.as_mut_ptr(),
                    vector.len(),
                    seed.as_mut_ptr(),
                    seed.len(),
                    hash.as_mut_ptr(),
                    hash.len(),
                )
            },
            Status::Ok as i32
        );
        let mut ct1 = [0u8; CT1_SIZE];
        let mut handle = 0;
        assert_eq!(
            unsafe {
                deep_mlkem_braid_v1_encaps1_from_random(
                    seed.as_ptr(),
                    seed.len(),
                    hash.as_ptr(),
                    hash.len(),
                    encaps_random.as_ptr(),
                    encaps_random.len(),
                    ct1.as_mut_ptr(),
                    ct1.len(),
                    &mut handle,
                )
            },
            Status::Ok as i32
        );
        let mut ct2 = [0u8; CT2_SIZE];
        let mut sender_secret = [0u8; SHARED_SECRET_SIZE];
        assert_eq!(
            unsafe {
                deep_mlkem_braid_v1_encaps2(
                    handle,
                    seed.as_ptr(),
                    seed.len(),
                    vector.as_ptr(),
                    vector.len(),
                    ct2.as_mut_ptr(),
                    ct2.len(),
                    sender_secret.as_mut_ptr(),
                    sender_secret.len(),
                )
            },
            Status::Ok as i32
        );
        let mut replay_ct2 = [0x55u8; CT2_SIZE];
        let mut replay_secret = [0x55u8; SHARED_SECRET_SIZE];
        assert_eq!(
            unsafe {
                deep_mlkem_braid_v1_encaps2(
                    handle,
                    seed.as_ptr(),
                    seed.len(),
                    vector.as_ptr(),
                    vector.len(),
                    replay_ct2.as_mut_ptr(),
                    replay_ct2.len(),
                    replay_secret.as_mut_ptr(),
                    replay_secret.len(),
                )
            },
            Status::InvalidHandle as i32
        );
        assert_eq!(replay_ct2, [0u8; CT2_SIZE]);
        assert_eq!(replay_secret, [0u8; SHARED_SECRET_SIZE]);

        let mut recipient_secret = [0u8; SHARED_SECRET_SIZE];
        assert_eq!(
            unsafe {
                deep_mlkem_braid_v1_decapsulate(
                    dk.as_ptr(),
                    dk.len(),
                    ct1.as_ptr(),
                    ct1.len(),
                    ct2.as_ptr(),
                    ct2.len(),
                    recipient_secret.as_mut_ptr(),
                    recipient_secret.len(),
                )
            },
            Status::Ok as i32
        );
        assert_eq!(sender_secret, recipient_secret);
    }

    #[test]
    fn concurrent_encaps2_has_exactly_one_consumer() {
        let (keygen_random, encaps_random) = deterministic_material();
        let mut dk = [0u8; DK_SIZE];
        let mut vector = [0u8; EK_VECTOR_SIZE];
        let mut seed = [0u8; EK_SEED_SIZE];
        let mut hash = [0u8; EK_HASH_SIZE];
        assert_eq!(
            unsafe {
                deep_mlkem_braid_v1_keypair_from_random(
                    keygen_random.as_ptr(),
                    keygen_random.len(),
                    dk.as_mut_ptr(),
                    dk.len(),
                    vector.as_mut_ptr(),
                    vector.len(),
                    seed.as_mut_ptr(),
                    seed.len(),
                    hash.as_mut_ptr(),
                    hash.len(),
                )
            },
            Status::Ok as i32
        );
        let mut ct1 = [0u8; CT1_SIZE];
        let mut handle = 0;
        assert_eq!(
            unsafe {
                deep_mlkem_braid_v1_encaps1_from_random(
                    seed.as_ptr(),
                    seed.len(),
                    hash.as_ptr(),
                    hash.len(),
                    encaps_random.as_ptr(),
                    encaps_random.len(),
                    ct1.as_mut_ptr(),
                    ct1.len(),
                    &mut handle,
                )
            },
            Status::Ok as i32
        );

        let invoke = move || {
            let mut ct2 = [0u8; CT2_SIZE];
            let mut secret = [0u8; SHARED_SECRET_SIZE];
            unsafe {
                deep_mlkem_braid_v1_encaps2(
                    handle,
                    seed.as_ptr(),
                    seed.len(),
                    vector.as_ptr(),
                    vector.len(),
                    ct2.as_mut_ptr(),
                    ct2.len(),
                    secret.as_mut_ptr(),
                    secret.len(),
                )
            }
        };
        let first = std::thread::spawn(invoke);
        let second = std::thread::spawn(move || {
            let mut ct2 = [0u8; CT2_SIZE];
            let mut secret = [0u8; SHARED_SECRET_SIZE];
            unsafe {
                deep_mlkem_braid_v1_encaps2(
                    handle,
                    seed.as_ptr(),
                    seed.len(),
                    vector.as_ptr(),
                    vector.len(),
                    ct2.as_mut_ptr(),
                    ct2.len(),
                    secret.as_mut_ptr(),
                    secret.len(),
                )
            }
        });
        let mut statuses = [
            first.join().expect("first thread"),
            second.join().expect("second thread"),
        ];
        statuses.sort_unstable();
        assert_eq!(statuses, [Status::Ok as i32, Status::InvalidHandle as i32]);
    }

    #[test]
    fn csprng_keygen_and_encapsulation_roundtrip() {
        let mut dk = [0u8; DK_SIZE];
        let mut vector = [0u8; EK_VECTOR_SIZE];
        let mut seed = [0u8; EK_SEED_SIZE];
        let mut hash = [0u8; EK_HASH_SIZE];
        assert_eq!(
            unsafe {
                deep_mlkem_braid_v1_keypair_generate(
                    dk.as_mut_ptr(),
                    dk.len(),
                    vector.as_mut_ptr(),
                    vector.len(),
                    seed.as_mut_ptr(),
                    seed.len(),
                    hash.as_mut_ptr(),
                    hash.len(),
                )
            },
            Status::Ok as i32
        );
        let mut ct1 = [0u8; CT1_SIZE];
        let mut handle = 0;
        assert_eq!(
            unsafe {
                deep_mlkem_braid_v1_encaps1_generate(
                    seed.as_ptr(),
                    seed.len(),
                    hash.as_ptr(),
                    hash.len(),
                    ct1.as_mut_ptr(),
                    ct1.len(),
                    &mut handle,
                )
            },
            Status::Ok as i32
        );
        let mut ct2 = [0u8; CT2_SIZE];
        let mut sender_secret = [0u8; SHARED_SECRET_SIZE];
        assert_eq!(
            unsafe {
                deep_mlkem_braid_v1_encaps2(
                    handle,
                    seed.as_ptr(),
                    seed.len(),
                    vector.as_ptr(),
                    vector.len(),
                    ct2.as_mut_ptr(),
                    ct2.len(),
                    sender_secret.as_mut_ptr(),
                    sender_secret.len(),
                )
            },
            Status::Ok as i32
        );
        let mut recipient_secret = [0u8; SHARED_SECRET_SIZE];
        assert_eq!(
            unsafe {
                deep_mlkem_braid_v1_decapsulate(
                    dk.as_ptr(),
                    dk.len(),
                    ct1.as_ptr(),
                    ct1.len(),
                    ct2.as_ptr(),
                    ct2.len(),
                    recipient_secret.as_mut_ptr(),
                    recipient_secret.len(),
                )
            },
            Status::Ok as i32
        );
        assert_eq!(sender_secret, recipient_secret);
    }

    #[test]
    fn ffi_rejects_null_lengths_overlap_and_double_free() {
        let mut output = [0x55u8; DK_SIZE];
        let status = unsafe {
            deep_mlkem_braid_v1_keypair_from_random(
                ptr::null(),
                KEYGEN_RANDOM_SIZE,
                output.as_mut_ptr(),
                output.len(),
                ptr::null_mut(),
                EK_VECTOR_SIZE,
                ptr::null_mut(),
                EK_SEED_SIZE,
                ptr::null_mut(),
                EK_HASH_SIZE,
            )
        };
        assert_eq!(status, Status::InvalidArgument as i32);
        assert_eq!(output, [0x55u8; DK_SIZE]);

        let mut vector_output = [0x55u8; EK_VECTOR_SIZE];
        let mut seed_output = [0x55u8; EK_SEED_SIZE];
        let mut hash_output = [0x55u8; EK_HASH_SIZE];
        let status = unsafe {
            deep_mlkem_braid_v1_keypair_from_random(
                [0u8; KEYGEN_RANDOM_SIZE].as_ptr(),
                KEYGEN_RANDOM_SIZE - 1,
                output.as_mut_ptr(),
                output.len(),
                vector_output.as_mut_ptr(),
                vector_output.len(),
                seed_output.as_mut_ptr(),
                seed_output.len(),
                hash_output.as_mut_ptr(),
                hash_output.len(),
            )
        };
        assert_eq!(status, Status::InvalidLength as i32);
        assert_eq!(output, [0x55u8; DK_SIZE]);
        assert_eq!(vector_output, [0x55u8; EK_VECTOR_SIZE]);
        assert_eq!(seed_output, [0x55u8; EK_SEED_SIZE]);
        assert_eq!(hash_output, [0x55u8; EK_HASH_SIZE]);

        let (keygen_random, encaps_random) = deterministic_material();
        let mut dk = [0u8; DK_SIZE];
        let mut vector = [0u8; EK_VECTOR_SIZE];
        let mut seed = [0u8; EK_SEED_SIZE];
        let mut hash = [0u8; EK_HASH_SIZE];
        assert_eq!(
            unsafe {
                deep_mlkem_braid_v1_keypair_from_random(
                    keygen_random.as_ptr(),
                    keygen_random.len(),
                    dk.as_mut_ptr(),
                    dk.len(),
                    vector.as_mut_ptr(),
                    vector.len(),
                    seed.as_mut_ptr(),
                    seed.len(),
                    hash.as_mut_ptr(),
                    hash.len(),
                )
            },
            Status::Ok as i32
        );
        let mut ct1 = [0u8; CT1_SIZE];
        let mut handle = 0;
        assert_eq!(
            unsafe {
                deep_mlkem_braid_v1_encaps1_from_random(
                    seed.as_ptr(),
                    seed.len(),
                    hash.as_ptr(),
                    hash.len(),
                    encaps_random.as_ptr(),
                    encaps_random.len(),
                    ct1.as_mut_ptr(),
                    ct1.len(),
                    &mut handle,
                )
            },
            Status::Ok as i32
        );
        assert_eq!(deep_mlkem_braid_v1_state_free(handle), Status::Ok as i32);
        assert_eq!(
            deep_mlkem_braid_v1_state_free(handle),
            Status::InvalidHandle as i32
        );

        let mut overlap = [0u8; DK_SIZE + EK_VECTOR_SIZE + EK_SEED_SIZE + EK_HASH_SIZE];
        let status = unsafe {
            deep_mlkem_braid_v1_keypair_from_random(
                keygen_random.as_ptr(),
                keygen_random.len(),
                overlap.as_mut_ptr(),
                DK_SIZE,
                overlap.as_mut_ptr().add(1),
                EK_VECTOR_SIZE,
                overlap.as_mut_ptr().add(DK_SIZE + EK_VECTOR_SIZE),
                EK_SEED_SIZE,
                overlap
                    .as_mut_ptr()
                    .add(DK_SIZE + EK_VECTOR_SIZE + EK_SEED_SIZE),
                EK_HASH_SIZE,
            )
        };
        assert_eq!(status, Status::Overlap as i32);
    }
}
