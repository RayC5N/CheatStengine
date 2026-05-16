#pragma once

#include <CheatStengine/Process/Process.h>

#include <Zydis/Zydis.h>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

struct PatternOptions {
    bool WildcardRelativeImmediates = true; // Always wildcard relative immediates (call/jmp targets).
    bool WildcardRipRelativeDisp = true; // Wildcard RIP-relative 32-bit displacements (e.g. mov rax, [rip+X]).
    bool WildcardAbsoluteAddresses = true; // Wildcard 64-bit absolute address operands (movabs).
    bool WildcardAllImmediates = true; // Wildcard ALL non-relative immediates as well.

    bool ShortestUnique = true; // Generate the pattern until the first unique match is found.
    size_t MaxPatternLength = 50; // Maximum pattern length in bytes.

    std::string Separator = " ";
    std::string Wildcard = "?";
};

struct PatternResult {
    std::string pattern;
    size_t byteCount = 0;
    size_t instrCount = 0;
    size_t wildcards = 0;
};

class PatternGenerator {
public:
    explicit PatternGenerator(
        PatternOptions options = {});

    std::optional<PatternResult> Generate(std::unique_ptr<Process>& process, uintptr_t address, uintptr_t start, uintptr_t end) const;

    // Convenience: format a pattern from an arbitrary byte + mask pair.
    // mask[i] == true  → byte i becomes "??"
    // mask[i] == false → byte i is emitted as hex
    std::string FormatPattern(const std::vector<uint8_t>& bytes, const std::vector<bool>& mask) const;

private:
    // Per-instruction: fill `mask` (same size as `bytes`) with true where wildcards go.
    void BuildMask(
        const ZydisDecodedInstruction& instr,
        const ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT],
        std::vector<bool>& mask) const;

    // Mark byte range [offset, offset+sizeBytes) in mask as wildcards, clipped to mask size.
    static void MarkRange(std::vector<bool>& mask, uint8_t offset, uint8_t sizeBytes);

    PatternOptions m_Options;
    ZydisDecoder m_Decoder;
};
