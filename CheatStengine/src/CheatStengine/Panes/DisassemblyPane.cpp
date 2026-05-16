#include "DisassemblyPane.h"

#include <CheatStengine/AddressEvaluator/Evaluator.h>
#include <CheatStengine/Assembly/Assembler.h>
#include <CheatStengine/MainLayer.h>
#include <CheatStengine/UI/ImGui/Fonts.h>
#include <CheatStengine/UI/ImGui/Menu.h>
#include <CheatStengine/Utils.h>
#include <Engine/Core/Application.h>

#include <IconsMaterialDesignIcons.h>
#include <imgui.h>
#include <imgui_stdlib.h>
#include <zasm/formatter/formatter.hpp>
#include <zasm/x86/mnemonic.hpp>

#include <CheatStengine/Tools/PatternGenerator.h>
#include <format>

static std::string FormatProtectionFlags(DWORD protection)
{
    std::string result;

    // Access flags
    if (protection & PAGE_NOACCESS) result += "NOACCESS ";
    if (protection & PAGE_READONLY) result += "READONLY ";
    if (protection & PAGE_READWRITE) result += "READWRITE ";
    if (protection & PAGE_WRITECOPY) result += "WRITECOPY ";
    if (protection & PAGE_EXECUTE) result += "EXECUTE ";
    if (protection & PAGE_EXECUTE_READ) result += "EXECUTE_READ ";
    if (protection & PAGE_EXECUTE_READWRITE) result += "EXECUTE_READWRITE ";
    if (protection & PAGE_EXECUTE_WRITECOPY) result += "EXECUTE_WRITECOPY ";

    // Type flags
    if (protection & PAGE_GUARD) result += "GUARD ";
    if (protection & PAGE_NOCACHE) result += "NOCACHE ";
    if (protection & PAGE_WRITECOMBINE) result += "WRITECOMBINE ";

    if (result.empty()) {
        result = "Unknown";
    }

    // Trim trailing space
    if (!result.empty() && result.back() == ' ') {
        result.pop_back();
    }

    return result;
}

DisassemblyPane::DisassemblyPane(State& state, ModalManager& modalManager, KeybindManager& keybindManager)
    : Pane(ICON_MDI_HAMMER_WRENCH " Disassembly", state)
    , m_Decoder(zasm::MachineMode::AMD64)
    , m_ModalManager(modalManager)
    , m_KeybindManger(keybindManager)
{
    m_ModalManager.RegisterModal("Goto Address", BIND_FN(DisassemblyPane::GotoAddressModal));
    m_ModalManager.RegisterModal("Assemble", BIND_FN(DisassemblyPane::AssembleModal));
    m_ModalManager.RegisterModal("Pattern Generator", BIND_FN(DisassemblyPane::PatternGeneratorModal));
    m_ModalManager.RegisterModal("Pattern Viewer", BIND_FN(DisassemblyPane::PatternViewerModal));
    m_KeybindManger.RegisterKeybind(
        "Goto Address",
        "Focuses the instruction at the specified address",
        "Disassembly", ImGuiKey_G);
    m_KeybindManger.RegisterKeybind(
        "Follow Instruction",
        "Follows the instruction at the selected line if it has an immediate operand that looks like an address",
        "Disassembly", ImGuiKey_Space);
    m_KeybindManger.RegisterKeybind("Assemble",
        "Opens the assemble modal for the currently focused instruction",
        "Disassembly", ImGuiKey_A);
    m_KeybindManger.RegisterKeybind("Go Back",
        "Jumps back to the previous instruction before you jumped to another address",
        "Disassembly", ImGuiKey_Escape);
    m_KeybindManger.RegisterKeybind("Generate Pattern",
        "Opens the pattern generator modal for the currently focused instruction",
        "Disassembly", ImGuiMod_Ctrl | ImGuiMod_Alt | ImGuiKey_S);
}

void DisassemblyPane::HandleKeybinds()
{
    if (!ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows)) {
        return;
    }

    if (m_KeybindManger.IsKeybindPressed("Go Back")) {
        if (!m_JumpHistory.empty()) {
            JumpPoint point = m_JumpHistory.top();
            m_JumpHistory.pop();
            ScrollToAddress(point.ScrollAddress);
            m_SelectedAddress = point.SelectedAddress;
        }
    }

    if (m_KeybindManger.IsKeybindPressed("Follow Instruction")) {
        auto it = m_Instructions.find(m_SelectedAddress);
        if (it != m_Instructions.end()) {
            const DisassemblyLine& line = it->second;
            const zasm::InstructionDetail* detail = std::get_if<zasm::InstructionDetail>(&line.Value);
            if (detail) {
                JumpToPointedInstruction(detail->getInstruction());
            }
        }
    }

    if (m_KeybindManger.IsKeybindPressed("Assemble")) {
        auto it = m_Instructions.find(m_SelectedAddress);
        if (it != m_Instructions.end()) {
            const DisassemblyLine& line = it->second;
            const zasm::InstructionDetail* detail = std::get_if<zasm::InstructionDetail>(&line.Value);
            if (detail) {
                m_ModalManager.OpenModal("Assemble", m_SelectedAddress);
            }
        }
    }

    if (m_KeybindManger.IsKeybindPressed("Goto Address")) {
        m_AddressInput.clear();
        m_ModalManager.OpenModal("Goto Address");
    }

    if (m_KeybindManger.IsKeybindPressed("Generate Pattern")) {
        m_ModalManager.OpenModal("Pattern Generator", m_SelectedAddress);
    }
}

void DisassemblyPane::Analyze(uintptr_t address)
{
    if (!m_State.Process->IsValid()) {
        return;
    }
    // std::optional<MEMORY_BASIC_INFORMATION> mbi = m_State.Process->Query(address);
    // if (!mbi) {
    //     return;
    // }
    // if (mbi->Protect & PAGE_NOACCESS) {
    //     return;
    // }

    uintptr_t start = address & ~0xFFF;
    INFO("Analyzing Address: 0x{:X}", address);
    INFO("  Start: 0x{:X}, Size: 0x{:X}", start, 0x1000);
    AnalyzePage(start, 0x1000);
}

void DisassemblyPane::AnalyzePage(uintptr_t pageAddr, size_t pageSize)
{
    // INFO("Analyzing page: 0x{:X} (size: 0x{:X})", pageAddr, pageSize);
    std::vector<uint8_t> code = m_State.Process->ReadBytes(pageAddr, pageSize);

    uintptr_t bytesDecoded = 0;
    while (bytesDecoded < code.size()) {
        zasm::Decoder::Result res = m_Decoder.decode(code.data() + bytesDecoded, code.size() - bytesDecoded, pageAddr + bytesDecoded);
        if (!res.hasValue()) {
            m_Decoder = zasm::Decoder(m_Decoder.getMode());
            m_Instructions[pageAddr + bytesDecoded] = DisassemblyLine { { code[bytesDecoded] }, std::monostate {} };
            // ERR("Decoding error at address 0x{:X}: {}", bytesDecoded, res.error().getErrorMessage());
            bytesDecoded++;
            continue;
        }

        zasm::InstructionDetail& detail = res.value();
        const zasm::Mem* mem0 = detail.getOperand(0).getIf<zasm::Mem>();
        if (mem0 && static_cast<ZydisRegister>(mem0->getBase().getId()) == ZYDIS_REGISTER_RIP && mem0->getDisplacement() == pageAddr + bytesDecoded + detail.getLength()) {
            uint64_t targetAddr = *reinterpret_cast<uint64_t*>(code.data() + bytesDecoded + detail.getLength());
            detail = zasm::InstructionDetail(
                detail.getAttribs(),
                detail.getMnemonic(),
                detail.getOperandCount(), detail.getOperands(), detail.getOperandsAccess(),
                detail.getOperandsVisibility(), detail.getCPUFlags(), detail.getCategory(), detail.getLength() + 8);
            detail.setOperand(0, zasm::Imm { targetAddr });
        }

        std::vector<uint8_t> instrBytes(code.begin() + bytesDecoded, code.begin() + bytesDecoded + detail.getLength());
        m_Instructions[pageAddr + bytesDecoded] = DisassemblyLine { instrBytes, detail };
        // const zasm::Instruction instr = instrDetail.getInstruction();
        // std::string formatted = zasm::formatter::toString(&instr);
        // INFO("0x{:X} (0x{:X}): {}", pageAddr + bytesDecoded, bytesDecoded, formatted);

        bytesDecoded += detail.getLength();
    }
}

void DisassemblyPane::HandleScrolling()
{
    int64_t scrollWheel = ImGui::GetIO().MouseWheel;
    if (scrollWheel > 0 && m_ScrollAddress > 0) {
        if (auto it = m_Instructions.lower_bound(m_ScrollAddress); it != m_Instructions.begin()) {
            ScrollToAddress((--it)->first);
        } else if (m_ScrollAddress > 0) {
            m_ScrollAddress--;
        }
    } else if (scrollWheel < 0) {
        if (auto it = m_Instructions.upper_bound(m_ScrollAddress); it != m_Instructions.end()
            && m_Instructions.contains(m_ScrollAddress)) {
            ScrollToAddress(it->first);
        } else {
            m_ScrollAddress++;
        }
    }
}

void DisassemblyPane::DrawDisassembly()
{
    size_t visibleInstructionCount = ImGui::GetContentRegionAvail().y / ImGui::GetTextLineHeightWithSpacing() + 1;

    Fonts::Push(Fonts::Type::JetBrainsMono);
    ImVec2 cursorPos = ImGui::GetCursorScreenPos();
    if (ImGui::BeginTable("Disassembly", 3, ImGuiTableFlags_Resizable | ImGuiTableFlags_BordersV | ImGuiTableFlags_BordersOuterH)) {
        ImGui::TableSetupColumn("Address");
        ImGui::TableSetupColumn("Bytes");
        ImGui::TableSetupColumn("Instruction");
        ImGui::TableHeadersRow();

        uintptr_t currentAddress = m_ScrollAddress;
        size_t instructionCount = 0;
        while (instructionCount++ < visibleInstructionCount) {
            ImGui::TableNextRow();
            uintptr_t address = currentAddress;

            bool isRowSelected = (m_SelectedAddress == currentAddress);

            ImGui::TableSetColumnIndex(0);
            ImVec2 rowMin = { cursorPos.x, ImGui::GetCursorScreenPos().y + ImGui::GetTextLineHeightWithSpacing() };
            ImGui::TableSetColumnIndex(2);
            ImVec2 rowMax = { ImGui::GetCursorScreenPos().x + ImGui::GetContentRegionMax().x, rowMin.y };

            std::ostringstream formattedBytes;
            std::string formattedInstruction;

            uintptr_t instructionAddress = currentAddress;
            std::optional<MODULEENTRY32> modEntry = Utils::GetModuleForAddress(currentAddress, m_State.Modules);
            if (!m_Instructions.contains(currentAddress)) {
                DrawDisassemblyRowUnknown(currentAddress, modEntry);
                currentAddress++;
            } else {
                const DisassemblyLine& line = m_Instructions[currentAddress];

                const overloads visitor = {
                    [this, &rowMin, &rowMax](const zasm::InstructionDetail& instrDetail) -> std::pair<std::string, size_t> {
                        const zasm::Instruction instr = instrDetail.getInstruction();

                        FormattedInstruction formatted = Formatter::Format(instr, Formatter::Options { .ImmediateFormatter = [this](uint64_t val) {
                            std::optional<MODULEENTRY32> modEntry = Utils::GetModuleForAddress(val, m_State.Modules);
                            if (modEntry) {
                                return std::format("{}+0x{:X}", modEntry->szModule, val - reinterpret_cast<uintptr_t>(modEntry->modBaseAddr));
                            }

                            return std::format("0x{:X}", val);
                        } });
                        if (instr.getMnemonic() == zasm::x86::Mnemonic::Ret) {
                            ImGui::GetWindowDrawList()->AddLine(rowMin, rowMax, ImGui::GetColorU32(ImGuiCol_Border));
                        }

                        DrawFormattedInstruction(formatted);

                        return { formatted.Text, instrDetail.getLength() };
                    },
                    [&line](std::monostate) -> std::pair<std::string, size_t> {
                        std::ostringstream oss;
                        oss << "db ";
                        for (size_t i = 0; i < line.Bytes.size(); i++) {
                            uint8_t byte = line.Bytes[i];
                            oss << std::hex << std::setfill('0') << std::setw(2) << std::uppercase << "0x" << static_cast<int>(byte);
                            if (i < line.Bytes.size() - 1) {
                                oss << ", ";
                            }
                        }

                        ImGui::Text("%s", oss.str().c_str());
                        return { oss.str(), 1 };
                    }
                };

                ImGui::TableSetColumnIndex(2);
                auto [formatted, length] = std::visit(visitor, line.Value);
                formattedInstruction = formatted;

                ImGui::TableSetColumnIndex(0);
                if (modEntry) {
                    ImGui::Text("%s+0x%llX", modEntry->szModule, currentAddress - reinterpret_cast<uintptr_t>(modEntry->modBaseAddr));
                } else {
                    ImGui::Text("0x%012llX", currentAddress);
                }

                for (size_t i = 0; i < line.Bytes.size(); i++) {
                    formattedBytes << std::hex << std::setfill('0') << std::setw(2) << std::uppercase << static_cast<int>(line.Bytes[i]);
                    if (i < line.Bytes.size() - 1) {
                        formattedBytes << " ";
                    }
                }

                ImGui::TableSetColumnIndex(1);
                ImGui::Text("%s", formattedBytes.str().c_str());

                currentAddress += length;
            }

            ImGui::TableSetColumnIndex(0);
            std::string selectableLabel = std::format("##selectable_{:X}", currentAddress);
            if (ImGui::Selectable(selectableLabel.c_str(), isRowSelected, ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowOverlap)) {
                m_SelectedAddress = address;
            }

            std::string popupLabel = std::format("##popup_{:X}", address);
            if (ImGui::BeginPopupContextItem(popupLabel.c_str())) {
                m_SelectedAddress = address;
                if (ImGui::BeginRoundedMenu("Copy")) {
                    if (ImGui::RoundedMenuItem("Address")) {
                        ImGui::SetClipboardText(std::format("0x{:012X}", address).c_str());
                    }
                    if (ImGui::RoundedMenuItem("Bytes")) {
                        ImGui::SetClipboardText(formattedBytes.str().c_str());
                    }
                    if (ImGui::RoundedMenuItem("Instruction")) {
                        ImGui::SetClipboardText(formattedInstruction.c_str());
                    }
                    if (modEntry) {
                        if (ImGui::RoundedMenuItem("RVA")) {
                            ImGui::SetClipboardText(std::format("0x{:X}", instructionAddress - reinterpret_cast<uintptr_t>(modEntry->modBaseAddr)).c_str());
                        }
                    }
                    ImGui::EndMenu();
                }
                if (ImGui::BeginRoundedMenu("Change Page Protection")) {
                    MEMORY_BASIC_INFORMATION mbi = m_State.Process->Query(address).value_or({});

                    if (ImGui::RoundedMenuItem("PAGE_NOACCESS", nullptr, mbi.Protect & PAGE_NOACCESS)) {
                        (void)m_State.Process->Protect(address, 0x1000, PAGE_NOACCESS);
                    }
                    if (ImGui::RoundedMenuItem("PAGE_READONLY", nullptr, mbi.Protect & PAGE_READONLY)) {
                        (void)m_State.Process->Protect(address, 0x1000, PAGE_READONLY);
                    }
                    if (ImGui::RoundedMenuItem("PAGE_READWRITE", nullptr, mbi.Protect & PAGE_READWRITE)) {
                        (void)m_State.Process->Protect(address, 0x1000, PAGE_READWRITE);
                    }
                    if (ImGui::RoundedMenuItem("PAGE_WRITECOPY", nullptr, mbi.Protect & PAGE_WRITECOPY)) {
                        (void)m_State.Process->Protect(address, 0x1000, PAGE_WRITECOPY);
                    }
                    if (ImGui::RoundedMenuItem("PAGE_EXECUTE", nullptr, mbi.Protect & PAGE_EXECUTE)) {
                        (void)m_State.Process->Protect(address, 0x1000, PAGE_EXECUTE);
                    }
                    if (ImGui::RoundedMenuItem("PAGE_EXECUTE_READ", nullptr, mbi.Protect & PAGE_EXECUTE_READ)) {
                        (void)m_State.Process->Protect(address, 0x1000, PAGE_EXECUTE_READ);
                    }
                    if (ImGui::RoundedMenuItem("PAGE_EXECUTE_READWRITE", nullptr, mbi.Protect & PAGE_EXECUTE_READWRITE)) {
                        (void)m_State.Process->Protect(address, 0x1000, PAGE_EXECUTE_READWRITE);
                    }
                    if (ImGui::RoundedMenuItem("PAGE_EXECUTE_WRITECOPY", nullptr, mbi.Protect & PAGE_EXECUTE_WRITECOPY)) {
                        (void)m_State.Process->Protect(address, 0x1000, PAGE_EXECUTE_WRITECOPY);
                    }

                    ImGui::EndMenu();
                }
                if (ImGui::RoundedMenuItem("Generate Pattern", m_KeybindManger.GetKeybindString("Generate Pattern").c_str())) {
                    m_ModalManager.OpenModal("Pattern Generator", address);
                }
                if (ImGui::RoundedMenuItem("Assemble", m_KeybindManger.GetKeybindString("Assemble").c_str())) {
                    m_ModalManager.OpenModal("Assemble");
                }
                ImGui::EndPopup();
            }
        }
        ImGui::EndTable();
    }
    Fonts::Pop();
}

void DisassemblyPane::DrawStatusBar()
{
    Fonts::Push(Fonts::Type::JetBrainsMono);
    ImGui::Separator();
    std::string protectionStr = "N/A";
    if (std::optional<MEMORY_BASIC_INFORMATION> mbi = m_State.Process->Query(m_SelectedAddress)) {
        protectionStr = FormatProtectionFlags(mbi->Protect);
    }
    ImGui::Text("Selected Address: 0x%012llX Protect: %s", m_SelectedAddress, protectionStr.c_str());
    Fonts::Pop();
}

void DisassemblyPane::DrawDisassemblyRowUnknown(uintptr_t address, std::optional<MODULEENTRY32> modEntry)
{
    ImGui::TableSetColumnIndex(0);
    if (modEntry) {
        ImGui::Text("%s+0x%llX", modEntry->szModule, address - reinterpret_cast<uintptr_t>(modEntry->modBaseAddr));
    } else {
        ImGui::Text("0x%012llX", address);
    }
    ImGui::TableSetColumnIndex(2);
    ImGui::Text("??");
}

void DisassemblyPane::Draw(double deltaTime)
{
    static double accumulator = 0.0;
    accumulator += deltaTime;
    if (accumulator >= 1.0) {
        Analyze(m_ScrollAddress);
        accumulator = 0.0;
    }

    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2 { 0.0f, 0.0f });
    ImGui::Begin(m_Name.c_str(), &m_Open);
    ImGui::PopStyleVar();

    HandleKeybinds();

    float statusBarHeight = ImGui::GetFrameHeightWithSpacing();
    ImVec2 contentSize = ImGui::GetContentRegionAvail();
    contentSize.y -= statusBarHeight;

    ImGui::BeginChild("ScrollingRegion", contentSize, ImGuiChildFlags_None, ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);

    if (ImGui::IsWindowHovered()) {
        HandleScrolling();
    }
    DrawDisassembly();

    ImGui::EndChild();

    DrawStatusBar();

    ImGui::End();
}

void DisassemblyPane::ScrollToAddress(uintptr_t address)
{
    m_ScrollAddress = address;
    if (!m_Instructions.contains(address)) {
        Analyze(address);
    }
}

void DisassemblyPane::JumpToAddress(uintptr_t address)
{
    m_JumpHistory.emplace(m_ScrollAddress, m_SelectedAddress);
    ScrollToAddress(address);
    m_SelectedAddress = address;
}

void DisassemblyPane::AssembleModal(const std::string& name, const std::any& payload)
{
    ImGui::SetNextWindowPos(ImGui::GetMainViewport()->GetCenter(), ImGuiCond_Appearing, ImVec2 { 0.5f, 0.5f });
    if (ImGui::BeginPopupModal(name.c_str(), nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
        if (ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows)
            && ImGui::IsKeyPressed(ImGuiKey_Escape)) {
            ImGui::CloseCurrentPopup();
        }

        if (ImGui::IsWindowAppearing()) {
            ImGui::SetKeyboardFocusHere();
        }

        static std::string assembly;
        ImGui::Text("Assemble instruction at 0x%llX", m_SelectedAddress);
        ImGui::InputTextMultiline("##source", &assembly);

        if (ImGui::Button("Assemble")) {
            Assembly::Assembler assembler;
            assembler.Assemble(assembly);
            const std::vector<zasm::Instruction>& instructions = assembler.GetInstructions();

            zasm::Program program(zasm::MachineMode::AMD64);
            zasm::x86::Assembler a(program);
            for (const zasm::Instruction& instruction : instructions) {
                a.emit(instruction);
            }

            zasm::Serializer serializer;
            zasm::Error res = serializer.serialize(program, 0);
            const uint8_t* code = serializer.getCode();
            size_t codeSize = serializer.getCodeSize();

            // for (size_t i = 0; i < codeSize; i++) {
            //     INFO("Byte {:d}: 0x{:02X}", i, code[i]);
            // }

            m_State.Process->WriteBuffer(m_SelectedAddress, code, codeSize);
            Analyze(m_SelectedAddress);
            ImGui::CloseCurrentPopup();
        }
        ImGui::SameLine();
        if (ImGui::Button("Cancel")) {
            ImGui::CloseCurrentPopup();
        }
        ImGui::EndPopup();
    }
}

void DisassemblyPane::GotoAddressInput()
{
    AddressEvaluator::Result result = AddressEvaluator::Evaluate(m_AddressInput, *m_State.Process);
    if (result.IsError()) {
        return;
    }

    uintptr_t address = result.Value;
    INFO("Going to address: 0x{:X}", address);
    JumpToAddress(address);
}

void DisassemblyPane::JumpToPointedInstruction(const zasm::Instruction& instr)
{
    INFO("Jumping to pointed instruction...");
    if (instr.getOperandCount() != 1) {
        return;
    }

    INFO("Instruction has 1 operand, checking if it's an immediate...");
    const zasm::Imm* imm = instr.getOperandIf<zasm::Imm>(0);
    if (!imm) {
        return;
    }

    uintptr_t address = imm->value<uintptr_t>();
    JumpToAddress(address);
}

void DisassemblyPane::GotoAddressModal(const std::string& name, const std::any& payload)
{
    ImGui::SetNextWindowPos(ImGui::GetMainViewport()->GetCenter(), ImGuiCond_Appearing, ImVec2 { 0.5f, 0.5f });
    if (ImGui::BeginPopupModal(name.c_str(), nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
        if (ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows)
            && ImGui::IsKeyPressed(ImGuiKey_Escape)) {
            ImGui::CloseCurrentPopup();
        }

        ImGui::Text("Fill in the address you want to go to");
        if (ImGui::IsWindowAppearing()) {
            ImGui::SetKeyboardFocusHere();
        }

        if (ImGui::InputText("Address", &m_AddressInput, ImGuiInputTextFlags_EnterReturnsTrue)) {
            GotoAddressInput();
            ImGui::CloseCurrentPopup();
        }

        if (ImGui::Button("OK", ImVec2 { 70.0f, 0 })) {
            GotoAddressInput();
            ImGui::CloseCurrentPopup();
        }
        ImGui::SameLine();
        if (ImGui::Button("Cancel", ImVec2 { 70.0f, 0 })) {
            ImGui::CloseCurrentPopup();
        }

        ImGui::EndPopup();
    }
}

void DisassemblyPane::PatternGeneratorModal(const std::string& name, const std::any& payload)
{
    ImGui::SetNextWindowPos(ImGui::GetMainViewport()->GetCenter(), ImGuiCond_Appearing, ImVec2 { 0.5f, 0.5f });
    if (ImGui::BeginPopupModal(name.c_str(), nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
        if (ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows)
            && ImGui::IsKeyPressed(ImGuiKey_Escape)) {
            ImGui::CloseCurrentPopup();
        }

        uintptr_t address = std::any_cast<uintptr_t>(payload);
        ImGui::Text("Generate pattern for instruction at 0x%llX", address);

        ImGui::Separator();
        ImGui::Text("Generator Options:");

        static PatternOptions options;

        // Checkbox options
        ImGui::Checkbox("Wildcard Relative Immediates", &options.WildcardRelativeImmediates);
        ImGui::Checkbox("Wildcard RIP Relative Displacement", &options.WildcardRipRelativeDisp);
        ImGui::Checkbox("Wildcard Absolute Addresses", &options.WildcardAbsoluteAddresses);
        ImGui::Checkbox("Wildcard All Immediates", &options.WildcardAllImmediates);
        ImGui::Checkbox("Shortest Unique Pattern", &options.ShortestUnique);

        // Slider for pattern length
        size_t min = 0, max = 300;
        ImGui::SliderScalar("Max Pattern Length", ImGuiDataType_U64, &options.MaxPatternLength, &min, &max);

        // Text inputs for separator and wildcard
        ImGui::InputText("Separator", &options.Separator);
        ImGui::InputText("Wildcard", &options.Wildcard);

        ImGui::Separator();

        if (ImGui::Button("Generate")) {
            std::optional<MODULEENTRY32> moduleEntry = Utils::GetModuleForAddress(address, m_State.Modules);
            size_t start = moduleEntry ? reinterpret_cast<uintptr_t>(moduleEntry->modBaseAddr) : 0;
            size_t end = moduleEntry ? reinterpret_cast<uintptr_t>(moduleEntry->modBaseAddr) + moduleEntry->modBaseSize : 0x7FFFFFFFFFFF;

            PatternGenerator generator(options);
            std::optional<PatternResult> pattern = generator.Generate(m_State.Process, address, start, end);
            if (pattern) {
                std::string patternStr = pattern->pattern;
                INFO("Generated pattern: {}", patternStr);
                m_ModalManager.OpenModal("Pattern Viewer", patternStr);
            } else {
                ERR("Failed to generate pattern for address 0x{:X}", address);
            }
            ImGui::CloseCurrentPopup();
        }
        ImGui::SameLine();
        if (ImGui::Button("Cancel")) {
            ImGui::CloseCurrentPopup();
        }

        ImGui::EndPopup();
    }
}

void DisassemblyPane::PatternViewerModal(const std::string& name, const std::any& payload)
{
    ImGui::SetNextWindowPos(ImGui::GetMainViewport()->GetCenter(), ImGuiCond_Appearing, ImVec2 { 0.5f, 0.5f });
    if (ImGui::BeginPopupModal(name.c_str(), nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
        if (ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows)
            && ImGui::IsKeyPressed(ImGuiKey_Escape)) {
            ImGui::CloseCurrentPopup();
        }

        std::string pattern = std::any_cast<std::string>(payload);

        ImGui::Text("The generated pattern is: %s", pattern.c_str());

        ImGui::Separator();

        if (ImGui::Button("Copy to Clipboard")) {
            ImGui::SetClipboardText(pattern.c_str());
            ImGui::CloseCurrentPopup();
        }
        ImGui::SameLine();
        if (ImGui::Button("Close")) {
            ImGui::CloseCurrentPopup();
        }

        ImGui::EndPopup();
    }
}

void DisassemblyPane::DrawFormattedInstruction(const FormattedInstruction& instr)
{
    if (instr.Text.empty()) {
        return;
    }

    size_t currentPos = 0;
    for (const Highlight& highlight : instr.Highlights) {
        const Range& range = highlight.Range;

        if (currentPos < range.Start) {
            ImGui::TextUnformatted(instr.Text.substr(currentPos, range.Start - currentPos).c_str());
            ImGui::SameLine(0, 0);
        }

        ImU32 color = IM_COL32(186, 194, 222, 255);
        switch (highlight.Type) {
            case Highlight::Ty::Mnemonic: color = IM_COL32(116, 199, 236, 255); break;
            case Highlight::Ty::Register: color = IM_COL32(243, 139, 168, 255); break;
            case Highlight::Ty::Displacement:
            case Highlight::Ty::Immediate: color = IM_COL32(250, 226, 174, 255); break;
        }
        ImGui::PushStyleColor(ImGuiCol_Text, color);
        ImGui::TextUnformatted(instr.Text.substr(range.Start, range.End - range.Start).c_str());
        ImGui::PopStyleColor();
        ImGui::SameLine(0, 0);

        currentPos = range.End;
    }

    if (currentPos < instr.Text.size()) {
        ImGui::TextUnformatted(instr.Text.substr(currentPos).c_str());
        ImGui::SameLine(0, 0);
    }

    ImGui::NewLine();
}
