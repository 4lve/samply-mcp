use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use linux_perf_data::linux_perf_event_reader::{
    BranchSampleFormat, Endianness, EventRecord, Mmap2FileId, RawData, ReadFormat, RecordParseInfo,
    SampleFormat,
};
use linux_perf_data::{AttributeDescription, PerfFileReader, PerfFileRecord};

const DEFAULT_CACHELINE_SIZE: u64 = 64;

#[derive(Debug)]
pub struct C2cProfile {
    pub arch: Option<String>,
    pub cpu_description: Option<String>,
    pub perf_version: Option<String>,
    pub event_names: Vec<String>,
    pub cacheline_size: u64,
    pub first_timestamp_ns: Option<u64>,
    pub last_timestamp_ns: Option<u64>,
    pub samples: Vec<C2cSample>,
    pub samples_with_callchains: usize,
    pub skipped_samples: usize,
    pub missing_data_address_samples: usize,
    pub missing_physical_address_samples: usize,
}

#[derive(Debug, Clone)]
pub struct C2cSample {
    pub timestamp_ns: Option<u64>,
    pub pid: i32,
    pub tid: i32,
    pub cpu: u32,
    pub thread_name: Arc<str>,
    pub instruction_address: u64,
    pub data_address: u64,
    pub physical_address: Option<u64>,
    pub weight: u64,
    pub instruction_latency: Option<u16>,
    pub data_source: MemoryDataSource,
    pub mapped_instruction: Option<MappedInstruction>,
    pub callchain: Arc<[C2cCallchainFrame]>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MappedInstruction {
    pub path: Arc<str>,
    pub relative_address: u64,
    pub build_id: Option<Arc<str>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct C2cCallchainFrame {
    pub instruction_address: u64,
    pub mapped_instruction: Option<MappedInstruction>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct MemoryDataSource {
    pub raw: u64,
}

impl MemoryDataSource {
    const OP_LOAD: u64 = 0x2;
    const OP_STORE: u64 = 0x4;
    const LVL_REM_CCE1: u64 = 0x400;
    const LVL_REM_CCE2: u64 = 0x800;
    const SNOOP_HITM: u64 = 0x10;
    const SNOOPX_PEER: u64 = 0x2;

    pub fn operation(self) -> &'static str {
        let operation = self.raw & 0x1f;
        match (
            operation & Self::OP_LOAD != 0,
            operation & Self::OP_STORE != 0,
        ) {
            (true, true) => "load_store",
            (true, false) => "load",
            (false, true) => "store",
            _ if operation & 0x8 != 0 => "prefetch",
            _ if operation & 0x10 != 0 => "execute",
            _ => "unknown",
        }
    }

    pub fn is_load(self) -> bool {
        self.raw & Self::OP_LOAD != 0
    }

    pub fn is_store(self) -> bool {
        self.raw & Self::OP_STORE != 0
    }

    pub fn is_locked(self) -> bool {
        self.field(24, 2) & 0x2 != 0
    }

    pub fn is_hitm(self) -> bool {
        self.field(19, 5) & Self::SNOOP_HITM != 0
    }

    pub fn is_peer(self) -> bool {
        self.field(38, 2) & Self::SNOOPX_PEER != 0
    }

    pub fn is_remote(self) -> bool {
        let level = self.field(5, 14);
        let explicit_remote_without_hops = self.field(37, 1) != 0 && self.field(43, 3) == 0;
        explicit_remote_without_hops || level & (Self::LVL_REM_CCE1 | Self::LVL_REM_CCE2) != 0
    }

    pub fn level(self) -> &'static str {
        match self.field(33, 4) {
            1 => "l1",
            2 => "l2",
            3 => "l3",
            4 => "l4",
            5 => "l2_miss_buffer",
            6 => "memory_side_cache",
            7 => "l0",
            8 => "uncached",
            9 => "cxl",
            10 => "io",
            11 => "any_cache",
            12 => "fill_buffer",
            13 => "ram",
            14 => "persistent_memory",
            _ => "unknown",
        }
    }

    fn field(self, shift: u32, bits: u32) -> u64 {
        (self.raw >> shift) & ((1_u64 << bits) - 1)
    }
}

#[derive(Debug, Clone)]
struct Mapping {
    start: u64,
    end: u64,
    page_offset: u64,
    path: Arc<str>,
    build_id: Option<Arc<str>>,
}

#[derive(Default)]
struct ProcessState {
    thread_names: HashMap<i32, Arc<str>>,
    mappings: HashMap<i32, BTreeMap<u64, Mapping>>,
    strings: HashMap<String, Arc<str>>,
    callchains: HashMap<Arc<[C2cCallchainFrame]>, ()>,
}

impl ProcessState {
    fn intern(&mut self, value: String) -> Arc<str> {
        if let Some(existing) = self.strings.get(&value) {
            return Arc::clone(existing);
        }
        let interned: Arc<str> = Arc::from(value.clone());
        self.strings.insert(value, Arc::clone(&interned));
        interned
    }

    fn add_mapping(&mut self, pid: i32, mapping: Mapping) {
        self.mappings
            .entry(pid)
            .or_default()
            .insert(mapping.start, mapping);
    }

    fn resolve_instruction(&self, pid: i32, address: u64) -> Option<MappedInstruction> {
        self.find_mapping(pid, address)
            .or_else(|| self.find_mapping(-1, address))
            .and_then(|mapping| {
                let relative_address = address
                    .checked_sub(mapping.start)?
                    .checked_add(mapping.page_offset)?;
                Some(MappedInstruction {
                    path: Arc::clone(&mapping.path),
                    relative_address,
                    build_id: mapping.build_id.clone(),
                })
            })
    }

    fn find_mapping(&self, pid: i32, address: u64) -> Option<&Mapping> {
        let (_, mapping) = self.mappings.get(&pid)?.range(..=address).next_back()?;
        (address < mapping.end).then_some(mapping)
    }

    fn intern_callchain(&mut self, frames: Vec<C2cCallchainFrame>) -> Arc<[C2cCallchainFrame]> {
        if let Some((existing, ())) = self.callchains.get_key_value(frames.as_slice()) {
            return Arc::clone(existing);
        }
        let frames: Arc<[C2cCallchainFrame]> = frames.into();
        self.callchains.insert(Arc::clone(&frames), ());
        frames
    }
}

pub fn load_profile(path: &Path) -> Result<C2cProfile> {
    let file =
        File::open(path).with_context(|| format!("failed to open perf data {}", path.display()))?;
    let reader = BufReader::new(file);
    let PerfFileReader {
        mut perf_file,
        mut record_iter,
    } = PerfFileReader::parse_file(reader).context("failed to parse perf.data header")?;

    let arch = perf_file.arch()?.map(ToOwned::to_owned);
    let cpu_description = perf_file.cpu_desc()?.map(ToOwned::to_owned);
    let perf_version = perf_file.perf_version()?.map(ToOwned::to_owned);
    let event_names = perf_file
        .event_attributes()
        .iter()
        .filter_map(AttributeDescription::name)
        .map(ToOwned::to_owned)
        .collect();

    let mut state = ProcessState::default();
    let mut samples = Vec::new();
    let mut skipped_samples = 0;
    let mut samples_with_callchains = 0;
    let mut missing_data_address_samples = 0;
    let mut missing_physical_address_samples = 0;
    let mut first_timestamp_ns: Option<u64> = None;
    let mut last_timestamp_ns: Option<u64> = None;

    while let Some(file_record) = record_iter.next_record(&mut perf_file)? {
        let PerfFileRecord::EventRecord { record, .. } = file_record else {
            continue;
        };

        match record.parse()? {
            EventRecord::Comm(comm) => {
                let name =
                    state.intern(String::from_utf8_lossy(&comm.name.as_slice()).into_owned());
                state.thread_names.insert(comm.tid, name);
            }
            EventRecord::Fork(fork) => {
                if fork.pid != fork.ppid
                    && let Some(parent) = state.mappings.get(&fork.ppid).cloned()
                {
                    state.mappings.insert(fork.pid, parent);
                }
                if let Some(parent_name) = state.thread_names.get(&fork.ptid).cloned() {
                    state.thread_names.insert(fork.tid, parent_name);
                }
            }
            EventRecord::Mmap(mmap) if mmap.is_executable => {
                let path =
                    state.intern(String::from_utf8_lossy(&mmap.path.as_slice()).into_owned());
                state.add_mapping(
                    mmap.pid,
                    Mapping {
                        start: mmap.address,
                        end: mmap.address.saturating_add(mmap.length),
                        page_offset: mmap.page_offset,
                        path,
                        build_id: None,
                    },
                );
            }
            EventRecord::Mmap2(mmap) if mmap.protection & 0x4 != 0 => {
                let path =
                    state.intern(String::from_utf8_lossy(&mmap.path.as_slice()).into_owned());
                let build_id = match mmap.file_id {
                    Mmap2FileId::BuildId(bytes) => Some(state.intern(hex_bytes(&bytes))),
                    Mmap2FileId::InodeAndVersion(_) => None,
                };
                state.add_mapping(
                    mmap.pid,
                    Mapping {
                        start: mmap.address,
                        end: mmap.address.saturating_add(mmap.length),
                        page_offset: mmap.page_offset,
                        path,
                        build_id,
                    },
                );
            }
            EventRecord::Sample(_) => {
                if !record
                    .parse_info
                    .sample_format
                    .contains(SampleFormat::DATA_SRC)
                {
                    skipped_samples += 1;
                    continue;
                }
                let sample = parse_memory_sample(record.data, &record.parse_info)
                    .context("failed to parse perf memory sample")?;
                let Some(data_address) = sample.data_address.filter(|address| *address != 0) else {
                    missing_data_address_samples += 1;
                    continue;
                };
                let physical_address = sample.physical_address.filter(|address| *address != 0);
                if physical_address.is_none() {
                    missing_physical_address_samples += 1;
                }
                if let Some(timestamp) = sample.timestamp_ns {
                    first_timestamp_ns =
                        Some(first_timestamp_ns.map_or(timestamp, |old| old.min(timestamp)));
                    last_timestamp_ns =
                        Some(last_timestamp_ns.map_or(timestamp, |old| old.max(timestamp)));
                }
                let pid = sample.pid.unwrap_or_default();
                let tid = sample.tid.unwrap_or_default();
                let thread_name = state
                    .thread_names
                    .get(&tid)
                    .cloned()
                    .unwrap_or_else(|| Arc::from("<unknown>"));
                let instruction_address = sample.instruction_address.unwrap_or_default();
                let callchain = sample
                    .callchain
                    .into_iter()
                    .filter(|address| *address != 0 && !is_callchain_context(*address))
                    .map(|address| C2cCallchainFrame {
                        instruction_address: address,
                        mapped_instruction: state.resolve_instruction(pid, address),
                    })
                    .collect::<Vec<_>>();
                let callchain = state.intern_callchain(callchain);
                samples_with_callchains += usize::from(!callchain.is_empty());
                samples.push(C2cSample {
                    timestamp_ns: sample.timestamp_ns,
                    pid,
                    tid,
                    cpu: sample.cpu.unwrap_or_default(),
                    thread_name,
                    instruction_address,
                    data_address,
                    physical_address,
                    weight: sample.weight.unwrap_or(1),
                    instruction_latency: sample.instruction_latency,
                    data_source: MemoryDataSource {
                        raw: sample.data_source,
                    },
                    mapped_instruction: state.resolve_instruction(pid, instruction_address),
                    callchain,
                });
            }
            _ => {}
        }
    }

    if samples.is_empty() {
        bail!("perf.data contains no memory samples with data addresses");
    }

    Ok(C2cProfile {
        arch,
        cpu_description,
        perf_version,
        event_names,
        cacheline_size: DEFAULT_CACHELINE_SIZE,
        first_timestamp_ns,
        last_timestamp_ns,
        samples,
        samples_with_callchains,
        skipped_samples,
        missing_data_address_samples,
        missing_physical_address_samples,
    })
}

#[derive(Debug, Default)]
struct ParsedMemorySample {
    instruction_address: Option<u64>,
    pid: Option<i32>,
    tid: Option<i32>,
    timestamp_ns: Option<u64>,
    data_address: Option<u64>,
    cpu: Option<u32>,
    callchain: Vec<u64>,
    weight: Option<u64>,
    instruction_latency: Option<u16>,
    data_source: u64,
    physical_address: Option<u64>,
}

fn parse_memory_sample(
    mut data: RawData<'_>,
    info: &RecordParseInfo,
) -> Result<ParsedMemorySample> {
    let format = info.sample_format;
    let mut sample = ParsedMemorySample::default();

    if format.contains(SampleFormat::IDENTIFIER) {
        read_u64(&mut data, info.endian)?;
    }
    if format.contains(SampleFormat::IP) {
        sample.instruction_address = Some(read_u64(&mut data, info.endian)?);
    }
    if format.contains(SampleFormat::TID) {
        sample.pid = Some(read_i32(&mut data, info.endian)?);
        sample.tid = Some(read_i32(&mut data, info.endian)?);
    }
    if format.contains(SampleFormat::TIME) {
        sample.timestamp_ns = Some(read_u64(&mut data, info.endian)?);
    }
    if format.contains(SampleFormat::ADDR) {
        sample.data_address = Some(read_u64(&mut data, info.endian)?);
    }
    if format.contains(SampleFormat::ID) {
        read_u64(&mut data, info.endian)?;
    }
    if format.contains(SampleFormat::STREAM_ID) {
        read_u64(&mut data, info.endian)?;
    }
    if format.contains(SampleFormat::CPU) {
        sample.cpu = Some(read_u32(&mut data, info.endian)?);
        read_u32(&mut data, info.endian)?;
    }
    if format.contains(SampleFormat::PERIOD) {
        read_u64(&mut data, info.endian)?;
    }
    if format.contains(SampleFormat::READ) {
        skip_read_format(&mut data, info)?;
    }
    if format.contains(SampleFormat::CALLCHAIN) {
        let count = usize::try_from(read_u64(&mut data, info.endian)?)
            .context("perf callchain is too large")?;
        if count > 1_000_000 {
            bail!("perf callchain exceeds the one-million-frame safety limit");
        }
        sample.callchain.reserve(count);
        for _ in 0..count {
            sample.callchain.push(read_u64(&mut data, info.endian)?);
        }
    }
    if format.contains(SampleFormat::RAW) {
        let size = read_u32(&mut data, info.endian)?;
        data.skip(size as usize)?;
    }
    if format.contains(SampleFormat::BRANCH_STACK) {
        let count = read_u64(&mut data, info.endian)?;
        if info
            .branch_sample_format
            .contains(BranchSampleFormat::HW_INDEX)
        {
            read_u64(&mut data, info.endian)?;
        }
        data.skip(checked_byte_count(count, 24)?)?;
    }
    if format.contains(SampleFormat::REGS_USER) {
        let abi = read_u64(&mut data, info.endian)?;
        if abi != 0 {
            data.skip(info.user_regs_count as usize * 8)?;
        }
    }
    if format.contains(SampleFormat::STACK_USER) {
        let size = read_u64(&mut data, info.endian)?;
        data.skip(usize::try_from(size).context("user stack is too large")?)?;
        if size != 0 {
            read_u64(&mut data, info.endian)?;
        }
    }
    if format.intersects(SampleFormat::WEIGHT | SampleFormat::WEIGHT_STRUCT) {
        let raw_weight = read_u64(&mut data, info.endian)?;
        if format.contains(SampleFormat::WEIGHT_STRUCT) {
            sample.weight = Some(raw_weight & 0xffff_ffff);
            sample.instruction_latency = Some(((raw_weight >> 32) & 0xffff) as u16);
        } else {
            sample.weight = Some(raw_weight);
        }
    }
    if format.contains(SampleFormat::DATA_SRC) {
        sample.data_source = read_u64(&mut data, info.endian)?;
    }
    if format.contains(SampleFormat::TRANSACTION) {
        read_u64(&mut data, info.endian)?;
    }
    if format.contains(SampleFormat::REGS_INTR) {
        let abi = read_u64(&mut data, info.endian)?;
        if abi != 0 {
            data.skip(info.intr_regs_count as usize * 8)?;
        }
    }
    if format.contains(SampleFormat::PHYS_ADDR) {
        sample.physical_address = Some(read_u64(&mut data, info.endian)?);
    }
    if format.contains(SampleFormat::AUX) {
        let size = read_u64(&mut data, info.endian)?;
        data.skip(usize::try_from(size).context("AUX sample is too large")?)?;
    }
    if format.contains(SampleFormat::CGROUP) {
        read_u64(&mut data, info.endian)?;
    }
    if format.contains(SampleFormat::DATA_PAGE_SIZE) {
        read_u64(&mut data, info.endian)?;
    }
    if format.contains(SampleFormat::CODE_PAGE_SIZE) {
        read_u64(&mut data, info.endian)?;
    }

    Ok(sample)
}

fn is_callchain_context(address: u64) -> bool {
    // PERF_CONTEXT_* markers are negative values in the unsigned callchain array.
    address >= (-4_095_i64) as u64
}

fn skip_read_format(data: &mut RawData<'_>, info: &RecordParseInfo) -> Result<()> {
    let read_format = info.read_format;
    if read_format.contains(ReadFormat::GROUP) {
        let count = read_u64(data, info.endian)?;
        if read_format.contains(ReadFormat::TOTAL_TIME_ENABLED) {
            read_u64(data, info.endian)?;
        }
        if read_format.contains(ReadFormat::TOTAL_TIME_RUNNING) {
            read_u64(data, info.endian)?;
        }
        let fields_per_value = 1 + usize::from(read_format.contains(ReadFormat::ID));
        data.skip(checked_byte_count(count, fields_per_value * 8)?)?;
    } else {
        read_u64(data, info.endian)?;
        if read_format.contains(ReadFormat::TOTAL_TIME_ENABLED) {
            read_u64(data, info.endian)?;
        }
        if read_format.contains(ReadFormat::TOTAL_TIME_RUNNING) {
            read_u64(data, info.endian)?;
        }
        if read_format.contains(ReadFormat::ID) {
            read_u64(data, info.endian)?;
        }
    }
    Ok(())
}

fn checked_byte_count(count: u64, item_size: usize) -> Result<usize> {
    usize::try_from(count)
        .ok()
        .and_then(|count| count.checked_mul(item_size))
        .context("perf sample array is too large")
}

fn read_u64(data: &mut RawData<'_>, endian: Endianness) -> Result<u64> {
    let mut bytes = [0_u8; 8];
    data.read_exact(&mut bytes)?;
    Ok(match endian {
        Endianness::LittleEndian => u64::from_le_bytes(bytes),
        Endianness::BigEndian => u64::from_be_bytes(bytes),
    })
}

fn read_u32(data: &mut RawData<'_>, endian: Endianness) -> Result<u32> {
    let mut bytes = [0_u8; 4];
    data.read_exact(&mut bytes)?;
    Ok(match endian {
        Endianness::LittleEndian => u32::from_le_bytes(bytes),
        Endianness::BigEndian => u32::from_be_bytes(bytes),
    })
}

fn read_i32(data: &mut RawData<'_>, endian: Endianness) -> Result<i32> {
    let mut bytes = [0_u8; 4];
    data.read_exact(&mut bytes)?;
    Ok(match endian {
        Endianness::LittleEndian => i32::from_le_bytes(bytes),
        Endianness::BigEndian => i32::from_be_bytes(bytes),
    })
}

fn hex_bytes(bytes: &[u8]) -> String {
    use std::fmt::Write;

    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut output, "{byte:02x}").expect("writing to a String cannot fail");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_amd_remote_cache_hitm() {
        let source = MemoryDataSource {
            raw: 0x836_2980_8042,
        };
        assert!(source.is_load());
        assert!(source.is_hitm());
        assert!(source.is_remote());
        assert_eq!(source.level(), "any_cache");
    }

    #[test]
    fn decodes_load_weight_structure() {
        let source = MemoryDataSource {
            raw: 0x1a_2908_1042,
        };
        assert!(source.is_load());
        assert!(!source.is_hitm());
        assert_eq!(source.level(), "ram");
    }

    #[test]
    fn parses_weight_struct_and_memory_fields() {
        use linux_perf_data::linux_perf_event_reader::RecordIdParseInfo;

        let sample_format = SampleFormat::IP
            | SampleFormat::TID
            | SampleFormat::TIME
            | SampleFormat::ADDR
            | SampleFormat::CPU
            | SampleFormat::CALLCHAIN
            | SampleFormat::WEIGHT_STRUCT
            | SampleFormat::DATA_SRC
            | SampleFormat::PHYS_ADDR;
        let info = RecordParseInfo {
            endian: Endianness::LittleEndian,
            sample_format,
            branch_sample_format: BranchSampleFormat::empty(),
            read_format: ReadFormat::empty(),
            common_data_offset_from_end: None,
            sample_regs_user: 0,
            user_regs_count: 0,
            sample_regs_intr: 0,
            intr_regs_count: 0,
            id_parse_info: RecordIdParseInfo {
                nonsample_record_id_offset_from_end: None,
                sample_record_id_offset_from_start: None,
            },
            nonsample_record_time_offset_from_end: None,
            sample_record_time_offset_from_start: Some(16),
        };
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0x1234_5678_u64.to_le_bytes());
        bytes.extend_from_slice(&42_i32.to_le_bytes());
        bytes.extend_from_slice(&84_i32.to_le_bytes());
        bytes.extend_from_slice(&1_000_000_u64.to_le_bytes());
        bytes.extend_from_slice(&0x2000_0044_u64.to_le_bytes());
        bytes.extend_from_slice(&7_u32.to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&3_u64.to_le_bytes());
        bytes.extend_from_slice(&(u64::MAX - 127).to_le_bytes());
        bytes.extend_from_slice(&0x1234_5678_u64.to_le_bytes());
        bytes.extend_from_slice(&0x1234_5000_u64.to_le_bytes());
        let weight_struct = 321_u64 | (654_u64 << 32) | (987_u64 << 48);
        bytes.extend_from_slice(&weight_struct.to_le_bytes());
        bytes.extend_from_slice(&0x836_2980_8042_u64.to_le_bytes());
        bytes.extend_from_slice(&0x4a8f_90044_u64.to_le_bytes());

        let sample = parse_memory_sample(RawData::from(bytes.as_slice()), &info).unwrap();
        assert_eq!(sample.instruction_address, Some(0x1234_5678));
        assert_eq!(sample.pid, Some(42));
        assert_eq!(sample.tid, Some(84));
        assert_eq!(sample.timestamp_ns, Some(1_000_000));
        assert_eq!(sample.data_address, Some(0x2000_0044));
        assert_eq!(sample.cpu, Some(7));
        assert_eq!(
            sample.callchain,
            vec![u64::MAX - 127, 0x1234_5678, 0x1234_5000]
        );
        assert!(is_callchain_context(sample.callchain[0]));
        assert!(!is_callchain_context(sample.callchain[1]));
        assert_eq!(sample.weight, Some(321));
        assert_eq!(sample.instruction_latency, Some(654));
        assert_eq!(sample.data_source, 0x836_2980_8042);
        assert_eq!(sample.physical_address, Some(0x4a8f_90044));
    }
}
