use anyhow::{Result, bail};
use gimli::Register;
use object::{Architecture as ObjectArchitecture, Endianness as ObjectEndianness};

use crate::model::{Architecture, Endianness};

pub fn object_architecture(architecture: Architecture) -> ObjectArchitecture {
    match architecture {
        Architecture::X86_64 => ObjectArchitecture::X86_64,
        Architecture::X86 => ObjectArchitecture::I386,
        Architecture::Arm => ObjectArchitecture::Arm,
        Architecture::Aarch64 => ObjectArchitecture::Aarch64,
    }
}

pub fn object_endianness(endianness: Endianness) -> ObjectEndianness {
    match endianness {
        Endianness::Little => ObjectEndianness::Little,
        Endianness::Big => ObjectEndianness::Big,
    }
}

pub fn gimli_endianness(endianness: Endianness) -> gimli::RunTimeEndian {
    match endianness {
        Endianness::Little => gimli::RunTimeEndian::Little,
        Endianness::Big => gimli::RunTimeEndian::Big,
    }
}

pub fn register(architecture: Architecture, name: &str) -> Result<Register> {
    let canonical = match architecture {
        Architecture::X86_64 => canonical_x86_64(name),
        Architecture::X86 => canonical_x86(name),
        Architecture::Arm => canonical_arm(name),
        Architecture::Aarch64 => canonical_aarch64(name),
    };
    let register = match architecture {
        Architecture::X86_64 => gimli::X86_64::name_to_register(&canonical),
        Architecture::X86 => gimli::X86::name_to_register(&canonical),
        Architecture::Arm => gimli::Arm::name_to_register(&canonical),
        Architecture::Aarch64 => gimli::AArch64::name_to_register(&canonical),
    };
    match register {
        Some(register) => Ok(register),
        None => bail!(
            "unknown {:?} DWARF register {name:?} (canonical {canonical:?})",
            architecture
        ),
    }
}

fn canonical_x86_64(name: &str) -> String {
    let lower = name.trim_start_matches('%').to_ascii_lowercase();
    let full = match lower.as_str() {
        "eax" | "ax" | "al" | "ah" => "rax",
        "edx" | "dx" | "dl" | "dh" => "rdx",
        "ecx" | "cx" | "cl" | "ch" => "rcx",
        "ebx" | "bx" | "bl" | "bh" => "rbx",
        "esi" | "si" | "sil" => "rsi",
        "edi" | "di" | "dil" => "rdi",
        "ebp" | "bp" | "bpl" => "rbp",
        "esp" | "sp" | "spl" => "rsp",
        "eip" | "rip" => "RA",
        "rflags" | "eflags" | "flags" => "rFLAGS",
        "fsbase" | "fs_base" => "fs.base",
        "gsbase" | "gs_base" => "gs.base",
        _ if lower.starts_with('e')
            && lower.len() >= 3
            && lower[1..].starts_with(|character: char| character.is_ascii_digit()) =>
        {
            return format!("r{}", &lower[1..]);
        }
        _ if matches!(lower.chars().last(), Some('d' | 'w' | 'b'))
            && lower.starts_with('r')
            && lower[1..lower.len() - 1]
                .chars()
                .all(|character| character.is_ascii_digit()) =>
        {
            return lower[..lower.len() - 1].to_string();
        }
        _ => return lower,
    };
    full.to_string()
}

fn canonical_x86(name: &str) -> String {
    let lower = name.trim_start_matches('%').to_ascii_lowercase();
    match lower.as_str() {
        "ax" | "al" | "ah" => "eax".into(),
        "cx" | "cl" | "ch" => "ecx".into(),
        "dx" | "dl" | "dh" => "edx".into(),
        "bx" | "bl" | "bh" => "ebx".into(),
        "sp" | "spl" => "esp".into(),
        "bp" | "bpl" => "ebp".into(),
        "si" | "sil" => "esi".into(),
        "di" | "dil" => "edi".into(),
        "eip" => "RA".into(),
        "fsbase" | "fs_base" => "fs.base".into(),
        "gsbase" | "gs_base" => "gs.base".into(),
        _ => lower,
    }
}

fn canonical_arm(name: &str) -> String {
    let upper = name.trim_start_matches('$').to_ascii_uppercase();
    match upper.as_str() {
        "FP" => "R11".into(),
        "IP" => "R12".into(),
        _ => upper,
    }
}

fn canonical_aarch64(name: &str) -> String {
    let upper = name.trim_start_matches('$').to_ascii_uppercase();
    if let Some(number) = upper.strip_prefix('W')
        && number.chars().all(|character| character.is_ascii_digit())
    {
        return format!("X{number}");
    }
    for prefix in ['B', 'H', 'S', 'D', 'Q'] {
        if let Some(number) = upper.strip_prefix(prefix)
            && number.chars().all(|character| character.is_ascii_digit())
        {
            return format!("V{number}");
        }
    }
    match upper.as_str() {
        "FP" => "X29".into(),
        "LR" => "X30".into(),
        "WSP" => "SP".into(),
        _ => upper,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_required_architecture_registers() {
        assert_eq!(register(Architecture::X86_64, "eax").unwrap(), Register(0));
        assert_eq!(
            register(Architecture::X86_64, "r12b").unwrap(),
            Register(12)
        );
        assert_eq!(
            register(Architecture::X86_64, "r15w").unwrap(),
            Register(15)
        );
        assert_eq!(register(Architecture::X86, "ebp").unwrap(), Register(5));
        assert_eq!(register(Architecture::Arm, "r11").unwrap(), Register(11));
        assert_eq!(register(Architecture::Arm, "sp").unwrap(), Register(13));
        assert_eq!(register(Architecture::Aarch64, "w7").unwrap(), Register(7));
        assert_eq!(register(Architecture::Aarch64, "q3").unwrap(), Register(67));
        assert_eq!(register(Architecture::Aarch64, "lr").unwrap(), Register(30));
    }

    #[test]
    fn rejects_synthetic_registers() {
        assert!(register(Architecture::X86_64, "temp0").is_err());
    }
}
