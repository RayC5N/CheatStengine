#include "PatternGenerator.h"
#include "PatternScanner.h"

#include <Engine/Core/Log.h>

#include <iomanip>
#include <sstream>

PatternGenerator::PatternGenerator(
    PatternOptions options)
    : m_Options(std::move(options))
{
    if (!ZYAN_SUCCESS(ZydisDecoderInit(
            &m_Decoder,
            ZYDIS_MACHINE_MODE_LONG_64,
            ZYDIS_STACK_WIDTH_64))) {
        ERR("Failed to initialize Zydis decoder");
    }
}

std::optional<PatternResult> PatternGenerator::Generate(std::unique_ptr<Process>& process, uintptr_t address, uintptr_t start, uintptr_t end) const
{
    std::vector<uint8_t> bytes = process->ReadBytes(address, m_Options.MaxPatternLength);
    if (bytes.empty()) {
        ERR("Failed to read bytes for pattern generation at address 0x{:X}", address);
        return std::nullopt;
    }

    PatternScanner scanner(process);

    PatternResult result;
    std::vector<bool> mask;

    size_t offset = 0;
    while (offset < bytes.size()) {
        ZydisDecodedInstruction instr {};
        ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT] {};

        ZyanStatus status = ZydisDecoderDecodeFull(
            &m_Decoder,
            bytes.data() + offset, bytes.size() - offset,
            &instr, operands);

        if (!ZYAN_SUCCESS(status)) {
            break; // Stop; can't decode further
        }

        std::vector<bool> instrMask(instr.length, false);
        BuildMask(instr, operands, instrMask);

        // Append instruction bytes and mask to the overall pattern mask
        mask.insert(mask.end(), instrMask.begin(), instrMask.end());

        offset += instr.length;
        result.instrCount++;

        // If we're generating the shortest unique pattern, we can stop as soon as we have at least one wildcard and a valid pattern.
        if (m_Options.ShortestUnique) {
            std::vector<uintptr_t> results = scanner.PatternScan(bytes, mask, start, end, 2);
            if (results.empty()) {
                ERR("Generated pattern does not match any instructions in the specified range, which is unexpected. Address: 0x{:X}, Pattern: {}", address, FormatPattern(bytes, mask));
                return std::nullopt;
            }
            if (results.size() == 1) {
                break;
            }
        }
    }

    while (!mask.empty() && mask.back()) {
        mask.pop_back();
    }

    result.byteCount = bytes.size();
    for (bool w : mask) {
        if (w) ++result.wildcards;
    }

    result.pattern = FormatPattern(bytes, mask);
    return result;
}

std::string PatternGenerator::FormatPattern(
    const std::vector<uint8_t>& bytes,
    const std::vector<bool>& mask) const
{
    std::ostringstream oss;
    oss << std::uppercase << std::hex << std::setfill('0');

    for (size_t i = 0; i < mask.size(); ++i) {
        if (i > 0)
            oss << m_Options.Separator;

        if (i < mask.size() && mask[i])
            oss << m_Options.Wildcard;
        else
            oss << std::setw(2) << static_cast<unsigned>(bytes[i]);
    }

    return oss.str();
}

void PatternGenerator::BuildMask(
    const ZydisDecodedInstruction& instr,
    const ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT],
    std::vector<bool>& mask) const
{
    // Immediates
    for (size_t i = 0; i < 2; ++i) {
        const auto& rawImm = instr.raw.imm[i];
        if (rawImm.size == 0) {
            continue;
        }

        const uint8_t sizeBytes = static_cast<uint8_t>((rawImm.size + 7) / 8);

        if ((rawImm.is_relative && m_Options.WildcardRelativeImmediates)
            || m_Options.WildcardAllImmediates) {
            MarkRange(mask, rawImm.offset, sizeBytes);
        }
    }

    // Displacement
    if (instr.raw.disp.size > 0) {
        const uint8_t dispSizeBytes = static_cast<uint8_t>((instr.raw.disp.size + 7) / 8);

        bool wildcard = false;

        // RIP-relative 32-bit displacement is almost always an address-derived offset
        if (m_Options.WildcardRipRelativeDisp) {
            for (ZyanU8 i = 0; i < instr.operand_count_visible; ++i) {
                const ZydisDecodedOperand& op = operands[i];
                if (op.type == ZYDIS_OPERAND_TYPE_MEMORY && op.mem.base == ZYDIS_REGISTER_RIP) {
                    wildcard = true;
                    break;
                }
            }
        }

        // 64-bit absolute address in displacement field (rare encoding, e.g. MOV [addr], rax)
        if ((m_Options.WildcardAbsoluteAddresses && instr.raw.disp.size == 64) || m_Options.WildcardAllImmediates) {
            wildcard = true;
        }

        if (wildcard) {
            MarkRange(mask, instr.raw.disp.offset, dispSizeBytes);
        }
    }

    // 3. Absolute 64-bit operand address (MOVABS / MOV moffs)

    // On x86-64, "MOV RAX, [0xDEADBEEFCAFEBABE]" encodes a full 64-bit
    // address after the opcode with no ModRM. Zydis exposes this via
    // the immediate field but marked as a memory offset.
    // We detect it by looking for MEMORY operands with no base/index
    // whose raw encoding sits in an imm slot.
    if (m_Options.WildcardAbsoluteAddresses) {
        for (ZyanU8 i = 0; i < instr.operand_count; ++i) {
            const ZydisDecodedOperand& op = operands[i];
            if (op.type == ZYDIS_OPERAND_TYPE_MEMORY
                && op.mem.base == ZYDIS_REGISTER_NONE
                && op.mem.index == ZYDIS_REGISTER_NONE
                && instr.raw.disp.size == 0) {
                // The address lives in imm[0] for moffs encodings
                const auto& rawImm = instr.raw.imm[0];
                MarkRange(mask, rawImm.offset, static_cast<uint8_t>(rawImm.size / 8));
            }
        }
    }
}

void PatternGenerator::MarkRange(
    std::vector<bool>& mask,
    uint8_t offset,
    uint8_t sizeBytes)
{
    for (uint8_t b = 0; b < sizeBytes; ++b) {
        const size_t idx = static_cast<size_t>(offset) + b;
        if (idx < mask.size()) {
            mask[idx] = true;
        }
    }
}