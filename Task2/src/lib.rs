#![allow(non_snake_case)]
use thiserror::Error;

pub fn xor_buffers(first_buffer: &str, second_buffer: &str) -> Result<String, XorError> {
    if first_buffer.len() != second_buffer.len() {
        return Err(XorError::LengthMismatch(
            first_buffer.len(),
            second_buffer.len(),
        ));
    }

    let length = first_buffer.len();
    let mut result = String::with_capacity(length);

    let first_base = find_base(first_buffer)?;
    let second_base = find_base(second_buffer)?;
    let base = if first_base == second_base {
        first_base
    } else {
        return Err(XorError::DifferentBases(first_base, second_base));
    };

    for (symbol_first, symbol_second) in first_buffer.chars().zip(second_buffer.chars()) {
        let value_first = symbol_first
            .to_digit(base as u32)
            .ok_or(XorError::InvalidCharacter(base, symbol_first))?;
        let value_second = symbol_second
            .to_digit(base as u32)
            .ok_or(XorError::InvalidCharacter(base, symbol_second))?;

        let xor_value = value_first ^ value_second;

        let xor_char = std::char::from_digit(xor_value, base as u32)
            .ok_or(XorError::FailedConvert)?;
        result.push(xor_char);
    }

    Ok(result)
}

fn find_base(buffer: &str) -> Result<usize, XorError> {
    if is_binary(buffer) {
        Ok(2)
    } else if is_octal(buffer) {
        Ok(8)
    } else if is_hex(buffer) {
        Ok(16)
    } else {
        Err(XorError::InvalidBase)
    }
}

fn is_hex(buffer: &str) -> bool {
    buffer.chars().into_iter().all(|symbol| {
        symbol.is_ascii_digit()
            || ('a'..='f').contains(&symbol)
            || ('A'..='F').contains(&symbol)
    })
}

fn is_octal(buffer: &str) -> bool {
    buffer
        .chars()
        .into_iter()
        .all(|symbol| ('0'..='7').contains(&symbol))
}

fn is_binary(buffer: &str) -> bool {
    buffer
        .chars()
        .into_iter()
        .all(|symbol| ('0'..='1').contains(&symbol))
}

#[derive(Debug, Error)]
pub enum XorError {
    #[error("Length mismatch. First has length {0}, Second has length {1}.")]
    LengthMismatch(usize, usize),

    #[error("Buffer has invalid base.")]
    InvalidBase,

    #[error("Buffers have different bases: {0} and {1}.")]
    DifferentBases(usize, usize),

    #[error("Invalid character was found for base {0}: {1}")]
    InvalidCharacter(usize, char),

    #[error("Failed to convert result XOR value to the char.")]
    FailedConvert,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_xor() {
        let buf1 = "1c0111001f01012341100061a10241b53535009181c";
        let buf2 = "686974207468652012321362756c16c277320657965";
        let expected = "746865206b69640353221303d46e5777420706c6179";

        let result = xor_buffers(buf1, buf2);
        let is_valid = matches!(result, Ok(result) if result == expected);
        assert!(is_valid);
    }

    #[test]
    fn test_binary_xor() {
        let buf1 = "1010";
        let buf2 = "1100";
        let expected = "0110";

        let result = xor_buffers(buf1, buf2);
        let is_valid = matches!(result, Ok(result) if result == expected);
        assert!(is_valid);
    }

    #[test]
    fn length_mismatch() {
        let buffer_1 = "aaafff";
        let buffer_2 = "aaaffff";

        let result = xor_buffers(buffer_1, buffer_2);
        let is_valid = matches!(result, Err(XorError::LengthMismatch(6, 7)));
        assert!(is_valid);
    }

    #[test]
    fn is_hex_valid() {
        let buffer = "48656c6c6f";

        let is_hex = is_hex(&buffer);
        assert!(is_hex);
    }

    #[test]
    fn is_hex_non_valid() {
        let buffer = "ae9i";

        let is_hex = is_hex(&buffer);
        assert!(!is_hex);
    }

    #[test]
    fn is_octal_valid() {
        let buffer = "123456";

        let is_octal = is_octal(&buffer);
        assert!(is_octal);
    }

    #[test]
    fn is_octal_non_valid() {
        let buffer = "193562";

        let is_octal = is_octal(&buffer);
        assert!(!is_octal);
    }

    #[test]
    fn is_binary_valid() {
        let buffer = "01011010101";

        let is_binary = is_binary(&buffer);
        assert!(is_binary);
    }

    #[test]
    fn is_binary_non_valid() {
        let buffer = "00010j1";

        let is_binary = is_binary(&buffer);
        assert!(!is_binary);
    }
}
