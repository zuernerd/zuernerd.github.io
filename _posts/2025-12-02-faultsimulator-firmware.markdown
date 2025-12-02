---
layout: post
title: "Fault Simulator Firmware Mode"
date:   2025-12-02 19:08:00 +0200
categories: [blog]
tags: [hardware-security, cybersecurity, embedded-systems, fault-simulation, security-research]
---
## Introduction

In my [previous blog post]({% post_url 2025-07-30-fault-simulator %}), I introduced a fault injection simulation tool I've been contributing to. While the tool was already useful for testing custom-instrumented code, it had a significant limitation: you needed to specially compile your test cases with custom macros to mark success and failure paths. This made it impractical to test real-world firmware binaries.

I left off with an idea: what if we could test arbitrary firmware ELF files directly, without requiring special instrumentation? Over the past weeks, I've implemented exactly that. This post demonstrates the new "firmware mode" and walks through testing a realistic bootloader scenario.

## New Features

To enable firmware-mode testing, I implemented several key features:

* **Custom success and failure addresses**: Define which code paths represent successful attacks or proper expected behavior directly by address.
* **Custom initial register values**: Start execution at any arbitrary function, not just `main()` or the Reset Handler. This is crucial for testing specific security-critical functions without running the entire start-up code of the firmware.
* **Code patches**: Patch out functions that rely on hardware interaction (like UART polling loops) that aren't emulated in Unicorn.
* **Additional memory region initialization**: Map peripheral registers, option bytes, and other memory regions that real hardware provides.
* **Binary data loading**: Initialize memory regions with content from binary files, such as flash option bytes containing security settings.
* **JSON5 configuration files**: More readable configuration format with support for comments, making complex setups easier to document and maintain.
* **Various bug fixes**

With these features the simulator should be able to analyze real firmware binaries that you might encounter in the field.

## The Test Case: STM32F103 Read Memory Command

To demonstrate these new capabilities, I vibe coded a re-implementation of the STM32F103 bootloader's [Read Memory command](https://www.st.com/resource/en/application_note/an3155-usart-protocol-used-in-the-stm32-bootloader-stmicroelectronics.pdf). This command is part of the chip's built-in DFU bootloader, which allows reading memory over UART—but only if Read Protection (RDP) is disabled.

The security model is straightforward: if RDP is enabled in the flash option bytes, attempts to read flash memory should be rejected with a NACK (0x1F). If RDP is disabled, the bootloader sends an ACK (0x79) and returns the requested data.

Here's the core logic (simplified):

```c
/* STM32F103 Read Memory Command with RDP Check */

#include <stdint.h>

/* STM32F103 Flash Option Bytes */
#define FLASH_OB_BASE       0x1FFFF800
#define FLASH_OB_RDP        (*(volatile uint16_t *)(FLASH_OB_BASE))

/* RDP levels */
#define RDP_LEVEL_0         0x00AA  /* No protection */
#define RDP_LEVEL_1         0x5555  /* Read protection enabled */

/* Check if Read Protection (RDP) is enabled */
static uint8_t check_rdp_enabled(void) {
    uint16_t rdp_value = FLASH_OB_RDP;
    
    /* If RDP byte is not 0xAA, protection is enabled */
    if ((rdp_value & 0xFF) != 0xAA) {
        return 1;  /* RDP enabled */
    }
    return 0;  /* RDP disabled */
}

/* Receive address with RDP check */
static void receive_address_with_rdp_check(void) {
    uint8_t addr_bytes[4];
    uint8_t checksum;
    uint8_t computed_checksum;
    
    /* Receive 4 address bytes */
    addr_bytes[0] = uart_receive_byte();
    addr_bytes[1] = uart_receive_byte();
    addr_bytes[2] = uart_receive_byte();
    addr_bytes[3] = uart_receive_byte();
    
    /* Receive checksum */
    checksum = uart_receive_byte();
    
    /* Compute checksum (XOR of all address bytes) */
    computed_checksum = addr_bytes[0] ^ addr_bytes[1] ^ addr_bytes[2] ^ addr_bytes[3];
    
    /* Verify checksum */
    if (checksum != computed_checksum) {
        uart_send_byte(0x1F);  /* NACK */
        return;
    }
    
    /* Build address (big-endian) */
    uint32_t address = ((uint32_t)addr_bytes[0] << 24) |
                       ((uint32_t)addr_bytes[1] << 16) |
                       ((uint32_t)addr_bytes[2] << 8)  |
                       ((uint32_t)addr_bytes[3]);
    
    /* Check if address is in Flash and RDP is enabled */
    if (address >= 0x08000000 && address < 0x08020000) {
        /* Flash memory */
        if (check_rdp_enabled()) {
            uart_send_byte(0x1F);  /* NACK - RDP blocks Flash reading */
            return;
        }
    }
    
    /* Address accepted */
    read_address = (uint8_t *)address;
    uart_send_byte(0x79);  /* ACK */
}
```

The full source code is available in the [fault_simulator_test_elf repository](https://github.com/zuernerd/fault_simulator_test_elf).

## Setting Up the Simulation

Let's assume we've received this firmware binary "over the fence" and need to assess its fault injection resilience. This scenario is typical in security assessments where you might not have access to the complete source code or build chain, or where you specifically want to test the actual production firmware without any modifications. Testing the release version as-is ensures you're evaluating the real attack surface rather than a modified variant.

Our first step is to analyze the ELF file in Ghidra to identify key addresses:

```
                         main.c:125 (4)
    0800010a ff f7 d3 ff     bl         check_rdp_enabled
                         main.c:125 (2)
    0800010e 48 b9           cbnz       r0,LAB_08000124
                         LAB_08000110
                         main.c:132 (4)
    08000110 06 4b           ldr        r3,[DAT_0800012c]
    08000112 1c 60           str        r4,[r3,#0x0]=>read_address
                         main.c:133 (6)
    08000114 79 20           movs       r0,#0x79
    08000116 ff f7 c1 ff     bl         uart_send_byte
                         LAB_0800011a
                         main.c:134 (2)
    0800011a f8 bd           pop        {r3,r4,r5,r6,r7,pc}
                         LAB_0800011c
                         main.c:112 (2)
    0800011c 1f 20           movs       r0,#0x1f
                         main.c:112 (4)
    0800011e ff f7 bd ff     bl         uart_send_byte
                         main.c:113 (2)
    08000122 fa e7           b          LAB_0800011a
                         LAB_08000124
                         main.c:126 (6)
    08000124 1f 20           movs       r0,#0x1f
    08000126 ff f7 b9 ff     bl         uart_send_byte
                         main.c:127 (6)
    0800012a f6 e7           b          LAB_0800011a
```

From this disassembly, we need to identify the addresses we want to use for our simulation. These will define what the simulator considers a successful attack versus expected behavior. It's important to carefully choose our starting point and success/failure addresses to ensure we cover the complete attack surface of the security-critical code:

* **Success address**: `0x08000114` – This is where the code sends ACK (0x79), indicating the RDP check was bypassed and the address was accepted. If a fault allows execution to reach here when it shouldn't, that's a successful attack.
* **Failure addresses**: These represent the expected secure behavior when RDP protection is active:
  * `0x08000124` – Sends NACK due to RDP check failing (this is what we want to happen)
  * `0x0800011c` – Sends NACK due to checksum mismatch
* **Entry point**: `0x08000130` – Start of `handle_read_memory_command()`. We'll begin execution here to focus on the security-critical logic.

By starting execution at `handle_read_memory_command()` instead of `main()`, we skip UART initialization and the command dispatch loop, focusing our simulation on the security-critical logic. This dramatically reduces computation time per fault injection attempt.

Here's our initial JSON5 configuration:

```json5
{
  threads: 6,
  max_instructions: 2000,
  no_compilation: true,
  no_check: true,
  elf: "../fault_simulator_test_elf/stm32f103_rdp_test.elf",
  trace: true,
  analysis: true,
  run_through: true,
  print_unicorn_errors: true,
  class: ["single"],
  faults: ["glitch_1"],
  
  // Success: Bypass RDP check and send ACK (0x79)
  success_addresses: [
    "0x08000114",
  ],
  
  // Failure: NACK due to RDP protection (0x1F)
  failure_addresses: [
    "0x08000124",  // NACK - RDP check failed
    "0x0800011c",  // NACK - Checksum mismatch
  ],
  
  initial_registers: {
    SP: "0x20005000",
    PC: "0x08000130",  // handle_read_memory_command()
    R0: "0x00000000", 
    LR: "0x080001c6",
  },
}
```

This configuration includes several important settings: `threads` specifies how many parallel simulations to run, `no_compilation` tells the simulator we're using a pre-compiled ELF file instead of compiling C source, and the `elf` path points to our firmware binary. We enable `trace` mode and `print_unicorn_errors` for our initial test run so we can see exactly where execution fails and what needs to be fixed. The `run_through` option attempts to complete execution even if issues occur, helping us identify all the problems in one go.

## Iterative Setup: Solving Emulation Issues

Let's run the initial configuration:

```bash
$ ./target/debug/fault_simulator --config test.json5
--- Fault injection simulator: 93e1a96-modified ---

Loading configuration from: test.json5
Provided elf file: ../fault_simulator_test_elf/stm32f103_rdp_test.elf

Using custom initial register context:
  LR: 0x08000178
  SP: 0x20005000
  R0: 0x00000000
  PC: 0x080000C8

Unicorn Error: WRITE_UNMAPPED at PC 0x080000C8 (accessing 0x20004FE8)
```

The first issue: the `push` instruction tries to access unmapped SRAM. We need to add memory regions for the STM32F103:

```json5
memory_regions: [
  // SRAM
  {
    address: "0x20000000",
    size: "0x5000",
  },
  // Peripherals (GPIOA, USART1, RCC)
  {
    address: "0x40000000",
    size: "0x20000",
  },
]
```

Running again, we hit a new problem:

```
0x8000082:  ldr.w  r3, [r2, #0x800]
0x8000086:  tst.w  r3, #0x20
0x800008A:  beq    #0x8000082
0x8000082:  ldr.w  r3, [r2, #0x800]
0x8000086:  tst.w  r3, #0x20
0x800008A:  beq    #0x8000082
...
```

We're stuck in an infinite loop inside `uart_receive_byte()`, polling for incoming data. Since we're not emulating actual UART hardware, this will never exit. The solution is to patch out the UART calls and inject data directly into registers.

Looking at the disassembly of `receive_address_with_rdp_check()`:

```
0800015e f8 b5           push       {r3,r4,r5,r6,r7,lr}
0800015e ff f7 8f ff     bl         uart_receive_byte
08000162 07 46           mov        r7,r0
08000164 ff f7 8c ff     bl         uart_receive_byte
08000168 04 46           mov        r4,r0
0800016a ff f7 89 ff     bl         uart_receive_byte
0800016e 05 46           mov        r5,r0
08000170 ff f7 86 ff     bl         uart_receive_byte
08000174 06 46           mov        r6,r0
08000176 ff f7 83 ff     bl         uart_receive_byte
```

We can replace the `bl uart_receive_byte; mov rX, r0` sequences with direct `movs` instructions. For testing, we'll inject the flash address `0x08001000`, which falls in the flash range that requires RDP checking.

The simulator's code patching feature allows us to specify patches either by raw addresses or by symbol names with offsets. Using symbols is particularly valuable: if we recompile the firmware and addresses shift due to code changes, symbol-based patches remain valid without requiring manual config updates. This makes iterative development and testing much more practical:

```json5
code_patches: [
  // addr_bytes[0] = 0x08 (r7)
  {
    symbol: "receive_address_with_rdp_check",
    offset: "2",
    data: "0xbf00bf002708",  // movs r7, #8; nop; nop
  },
  // addr_bytes[1] = 0x00 (r4)
  {
    symbol: "receive_address_with_rdp_check",
    offset: "8",
    data: "0xbf00bf002400",  // movs r4, #0; nop; nop
  },
  // addr_bytes[2] = 0x10 (r5)
  {
    symbol: "receive_address_with_rdp_check",
    offset: "0xE",
    data: "0xbf00bf002510",  // movs r5, #16; nop; nop
  },
  // addr_bytes[3] = 0x00 (r6)
  {
    symbol: "receive_address_with_rdp_check",
    offset: "0x14",
    data: "0xbf00bf002600",  // movs r6, #0; nop; nop
  },
  // checksum = 0x08 ^ 0x00 ^ 0x10 ^ 0x00 = 0x18
  {
    symbol: "receive_address_with_rdp_check",
    offset: "0x1A",
    data: "0xbf002018",  // movs r0, #24; nop
  },
]
```

Running again:

```
Unicorn Error: READ_UNMAPPED at PC 0x080000B6 (accessing 0x1FFFF800)
```

Great! We've reached the actual RDP check. The code is trying to read the flash option bytes at `0x1FFFF800`, which don't exist in our emulated memory. We need to add this region and initialize it with RDP enabled (`0x5555`):

```json5
memory_regions: [
  // ... existing regions ...
  
  // Flash Option Bytes
  {
    address: "0x1FFFF000",
    size: "0x1000",
    file: "rdp_option_bytes.bin",  // Binary with RDP value 0x5555 at offset 0x800
  },
]
```

The binary file contains the RDP value at the correct offset. Now when we run:

```
Successfully mapped memory region: 0x1FFFF000 - 0x20000000 (4096 bytes)
Wrote 4096 bytes of data to memory region at 0x1FFFF000

uint16_t rdp_value = FLASH_OB_RDP;
0x80000B4:  ldr    r3, [pc, #0xc]
0x80000B6:  ldrh   r0, [r3]
0x80000B8:  uxtb   r0, r0
0x80000BA:  subs   r0, #0xaa
0x80000BC:  it     ne
0x80000BE:  movs   r0, #1
0x80000C0:  bx     lr

0x800010E:  cbnz   r0, #0x8000124
0x8000124:  movs   r0, #0x1f
0x8000126:  bl     uart_send_byte
```

Success! The simulation runs through completely and ends at failure address `0x8000124`, sending NACK as expected when RDP is enabled. Our setup is now complete.

## Running the Fault Injection Campaign

Now for the actual attack simulation. Here's our final configuration with trace mode disabled for performance:

```json5
{
// Configuration for STM32F103 Read Memory with RDP Test
{
  threads: 6,
  max_instructions: 2000,
  no_compilation: true,
  no_check: true,
  elf: "stm32f103_rdp_test.elf",
  trace: false,
  analysis: true,
  run_through: true,
  print_unicorn_errors: false,
  class: ["single"],
  faults: ["glitch_1"],
  
  // Success: Bypass RDP check and send ACK (0x79)
  success_addresses: [
    "0x08000114",  // Send ACK after accepting address (bypassed RDP)
  ],
  
  // Failure: NACK due to RDP protection (0x1F)
  failure_addresses: [
    "0x08000124",  // NACK - RDP check failed (address in Flash with RDP enabled)
    "0x0800011c",  // NACK - Checksum mismatch
  ],
  
  initial_registers: {
    SP: "0x20005000",        // Top of SRAM
    PC: "0x080000c8",        // receive_address_with_rdp_check() - skip UART init and command loop
    R0: "0x00000000",
    LR: "0x08000178",        // Return to main if needed
  },
  
  code_patches: [
    // Inject address bytes directly instead of waiting for UART
    // Testing Flash address: 0x08001000
    // addr_bytes[0] = 0x08 (r7)
    // Replace: bl uart_receive_byte; mov r7, r0
    {
      symbol: "receive_address_with_rdp_check",
      offset: "2",
      data: "0xbf00bf002708",  // movs r7, #8; nop; nop (6 bytes total)
    },
    // addr_bytes[1] = 0x00 (r4)
    // Replace: bl uart_receive_byte; mov r4, r0
    {
      symbol: "receive_address_with_rdp_check",
      offset: "8",
      data: "0xbf00bf002400",  // movs r4, #0; nop; nop (6 bytes total)
    },
    // addr_bytes[2] = 0x10 (r5)
    // Replace: bl uart_receive_byte; mov r5, r0
    {
      symbol: "receive_address_with_rdp_check",
      offset: "0xE",
      data: "0xbf00bf002510",  // movs r5, #16; nop; nop (6 bytes total)
    },
    // addr_bytes[3] = 0x00 (r6)
    // Replace: bl uart_receive_byte; mov r6, r0
    {
      symbol: "receive_address_with_rdp_check",
      offset: "0x14",
      data: "0xbf00bf002600",  // movs r6, #0; nop; nop (6 bytes total)
    },
    // checksum = 0x08 ^ 0x00 ^ 0x10 ^ 0x00 = 0x18 (r0)
    // Replace: bl uart_receive_byte (4 bytes only, no mov after)
    {
      symbol: "receive_address_with_rdp_check",
      offset: "0x1A",
      data: "0xbf002018",  // movs r0, #24; nop (4 bytes total)
    },
  ],
  
  memory_regions: [
    // SRAM
    {
      address: "0x20000000",
      size: "0x5000",
    },
    // Flash Option Bytes region (page-aligned)
    // Contains RDP protection value at 0x1FFFF800
    {
      address: "0x1FFFF000",
      size: "0x1000",
      file: "rdp_option_bytes.bin",  // Binary with RDP value 0x5555 at offset 0x800
    },
    // Peripherals (GPIOA, USART1, RCC)
    {
      address: "0x40000000",
      size: "0x20000",
    },
  ],
}
```

Running the simulation:

```bash
$ ./target/debug/fault_simulator --config test.json5
--- Fault injection simulator: 93e1a96-modified ---

Run fault simulations:
Running simulation for faults: [Glitch (glitch_1)]
-> 37 attacks executed, 2 successful

Attack number 1
0x80000F6:  orr.w r4, r4, r7, lsl #24 -> Glitch (glitch_1)
"/home/domi/fault_simulator_test_elf/main.c":117

Attack number 2
0x800010E:  cbnz r0, #0x8000124 -> Glitch (glitch_1)
"/home/domi/fault_simulator_test_elf/main.c":125

Overall tests executed 37
```

Out of 37 single-instruction skip attempts, we found 2 successful attacks.

**Attack #1** targets the address reconstruction at `0x080000F6`. By skipping the `orr.w r4, r4, r7, lsl #24` instruction, the most significant byte (stored in `r7 = 0x08`) is never incorporated into the final address. The address value in `r4` ends up as `0x00001000` instead of `0x08001000`, placing it outside the flash memory range (`0x08000000` - `0x08020000`). This causes the subsequent range check at line 123 to pass, bypassing the RDP protection check entirely.

**Attack #2** is more direct: skipping the conditional branch `cbnz r0, #0x8000124` at `0x0800010E`. This instruction should branch to the NACK handler when `check_rdp_enabled()` returns true (non-zero). By skipping it, execution falls through to the success path at `0x08000110`, bypassing RDP protection entirely.

## Conclusion

The new firmware mode extends the fault injection simulator from a research tool into something that can analyze real-world binaries. The ability to:

* Define success/failure by addresses rather than instrumentation
* Start execution at arbitrary functions
* Patch hardware-dependent code
* Initialize realistic memory layouts

...makes it possible to test firmware "as-is" without source modifications.

The iterative setup process of mapping memory, patching functions, and loading initialization data might seem involved at first. However, once configured, you can run thousands of fault scenarios in minutes, something completely impractical with physical hardware. Additionally, using symbol-based addressing for patches and configuration means that changes between firmware iterations remain easily maintainable, as the configuration adapts automatically when the code is recompiled.

The project demonstrates a realistic firmware security assessment scenario. With just two successful instruction skips, we found exploitable vulnerabilities. This is the kind of analysis that should be performed during secure boot development, before firmware is shipped to production.

These features are work in progress. I hope to improve both the workflow and performance with future contributions. As with any actively developed tool, there may be bugs, so be arare.
 