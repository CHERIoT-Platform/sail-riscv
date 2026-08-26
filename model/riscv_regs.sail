/*=======================================================================================*/
/*  This Sail RISC-V architecture model, comprising all files and                        */
/*  directories except where otherwise noted is subject the BSD                          */
/*  two-clause license in the LICENSE file.                                              */
/*                                                                                       */
/*  SPDX-License-Identifier: BSD-2-Clause                                                */
/*=======================================================================================*/

/* program counter */

register PC       : xlenbits
register nextPC   : xlenbits

/* internal state to hold instruction bits for faulting instructions */
register instbits : xlenbits

/* register file and accessors */

register x1  : regtype
register x2  : regtype
register x3  : regtype
register x4  : regtype
register x5  : regtype
register x6  : regtype
register x7  : regtype
register x8  : regtype
register x9  : regtype
register x10 : regtype
register x11 : regtype
register x12 : regtype
register x13 : regtype
register x14 : regtype
register x15 : regtype
register x16 : regtype
register x17 : regtype
register x18 : regtype
register x19 : regtype
register x20 : regtype
register x21 : regtype
register x22 : regtype
register x23 : regtype
register x24 : regtype
register x25 : regtype
register x26 : regtype
register x27 : regtype
register x28 : regtype
register x29 : regtype
register x30 : regtype
register x31 : regtype

// Forward declaration: rvfi_rX is the RVFI source-register hook,
// called from rX below. The actual body comes after rX (inside the
// $ifdef RVFI_DII block alongside rvfi_wX) to keep the two RVFI
// hooks together. The val declaration here is enough to make the
// callee visible to the rX function above.
val rvfi_rX : forall 'n, 0 <= 'n < 32. (regno('n), xlenbits) -> unit
val rvfi_rX65 : forall 'n 'm, 0 <= 'n < 32 & 65 <= 'm. (regno('n), bits('m)) -> unit
val rvfi_wX65 : forall 'n 'm, 0 <= 'n < 32 & 65 <= 'm. (regno('n), bits('m)) -> unit

val rX : forall 'n, 0 <= 'n < 32. regno('n) -> xlenbits
function rX r = {
  if rv32e_register_file & (r >= 16) then
    throw Error_not_rv32e_register();

  let v : regtype =
    match r {
      0 => zero_reg,
      1 => x1,
      2 => x2,
      3 => x3,
      4 => x4,
      5 => x5,
      6 => x6,
      7 => x7,
      8 => x8,
      9 => x9,
      10 => x10,
      11 => x11,
      12 => x12,
      13 => x13,
      14 => x14,
      15 => x15,
      15 => x15,
      16 => x16,
      17 => x17,
      18 => x18,
      19 => x19,
      20 => x20,
      21 => x21,
      22 => x22,
      23 => x23,
      24 => x24,
      25 => x25,
      26 => x26,
      27 => x27,
      28 => x28,
      29 => x29,
      30 => x30,
      31 => x31,
      _  => throw Error_not_rv32e_register()
    };
  let xval = regval_from_reg(v);
  // Populate the RVFI source-register slots so the exec packet
  // records which register was read and the value returned. This is
  // a no-op in non-RVFI builds (see the $else stub below).
  rvfi_rX(r, xval);
  xval
}

$ifdef RVFI_DII
val rvfi_wX : forall 'n, 0 <= 'n < 32. (regno('n), xlenbits) -> unit
function rvfi_wX (r,v) = {
  rvfi_int_data[rvfi_rd_wdata] = zero_extend(v);
  rvfi_int_data[rvfi_rd_addr] = to_bits(8,r);
  rvfi_int_data_present = true;
  rvfi_v1_rd_wdata72 = zero_extend(v);
}

function rvfi_wX65 (r, v) = {
  rvfi_int_data[rvfi_rd_addr] = to_bits(8,r);
  rvfi_int_data_present = true;
  rvfi_v1_rd_wdata72 = zero_extend(truncate(v, 65));
}

// Read-side analogue of rvfi_wX. Fills the rs1 slot on the first call
// of each step, the rs2 slot on the second, and drops further calls
// on the floor. The slot counter is reset by rvfi_zero_exec_packet().
//
// All instructions read their source registers via rX before doing
// anything else (Sail's wX path can't be reached without first
// computing the input value), so the first two slots reliably end
// up holding the instruction's actual rs1 / rs2.
// (val rvfi_rX is forward-declared near the top of the file so rX can call it.)
function rvfi_rX (r, v) = {
  match rvfi_int_read_slot {
    0b00 => {
      rvfi_int_data[rvfi_rs1_addr]  = to_bits(8, r);
      rvfi_int_data[rvfi_rs1_rdata] = zero_extend(v);
      rvfi_int_read_slot = 0b01;
      rvfi_int_data_present = true;
    },
    0b01 => {
      rvfi_int_data[rvfi_rs2_addr]  = to_bits(8, r);
      rvfi_int_data[rvfi_rs2_rdata] = zero_extend(v);
      rvfi_int_read_slot = 0b10;
      rvfi_int_data_present = true;
    },
    _ => ()  // both slots already filled; ignore extra reads
  }
}

function rvfi_rX65 (r, v) = {
  let v72 : bits(72) = zero_extend(truncate(v, 65));

  match rvfi_int_read_slot {
    0b00 => {
      rvfi_int_data[rvfi_rs1_addr] = to_bits(8, r);
      rvfi_v1_rs1_data72 = v72;

      rvfi_int_read_slot = 0b01;
      rvfi_int_data_present = true;
    },
    0b01 => {
      rvfi_int_data[rvfi_rs2_addr] = to_bits(8, r);
      rvfi_v1_rs2_data72 = v72;

      rvfi_int_read_slot = 0b10;
      rvfi_int_data_present = true;
    },
    _ => ()
  }
}

$else
val rvfi_wX : forall 'n, 0 <= 'n < 32. (regno('n), xlenbits) -> unit
function rvfi_wX (r,v) = ()
function rvfi_wX65 (r,v) = ()
// rvfi_rX val is forward-declared at the top of the file; body here.
function rvfi_rX (r, v) = ()
function rvfi_rX65 (r, v) = ()
$endif

val wX : forall 'n, 0 <= 'n < 32. (regno('n), xlenbits) -> unit
function wX (r, in_v) = {
  if rv32e_register_file & (r >= 16) then
    throw Error_not_rv32e_register();

  let v = regval_into_reg(in_v);
  match r {
    0  => (),
    1  => x1 = v,
    2  => x2 = v,
    3  => x3 = v,
    4  => x4 = v,
    5  => x5 = v,
    6  => x6 = v,
    7  => x7 = v,
    8  => x8 = v,
    9  => x9 = v,
    10 => x10 = v,
    11 => x11 = v,
    12 => x12 = v,
    13 => x13 = v,
    14 => x14 = v,
    15 => x15 = v,
    15 => x15 = v,
    16 => x16 = v,
    17 => x17 = v,
    18 => x18 = v,
    19 => x19 = v,
    20 => x20 = v,
    21 => x21 = v,
    22 => x22 = v,
    23 => x23 = v,
    24 => x24 = v,
    25 => x25 = v,
    26 => x26 = v,
    27 => x27 = v,
    28 => x28 = v,
    29 => x29 = v,
    30 => x30 = v,
    31 => x31 = v,
    _  => throw Error_not_rv32e_register()
  };
  if (r != 0) then {
     rvfi_wX(r, in_v);
     if   get_config_print_reg()
     then print_reg("x" ^ dec_str(r) ^ " <- " ^ RegStr(v));
  }
}

function rX_bits(i: bits(5)) -> xlenbits = rX(unsigned(i))

function wX_bits(i: bits(5), data: xlenbits) -> unit = {
  wX(unsigned(i)) = data
}

overload X = {rX_bits, wX_bits, rX, wX}

/* register names */

val reg_name_abi : regidx -> string

function reg_name_abi(r) = {
  match (r) {
    0b00000 => "zero",
    0b00001 => "ra",
    0b00010 => "sp",
    0b00011 => "gp",
    0b00100 => "tp",
    0b00101 => "t0",
    0b00110 => "t1",
    0b00111 => "t2",
    0b01000 => "fp",
    0b01001 => "s1",
    0b01010 => "a0",
    0b01011 => "a1",
    0b01100 => "a2",
    0b01101 => "a3",
    0b01110 => "a4",
    0b01111 => "a5",
    0b10000 => "a6",
    0b10001 => "a7",
    0b10010 => "s2",
    0b10011 => "s3",
    0b10100 => "s4",
    0b10101 => "s5",
    0b10110 => "s6",
    0b10111 => "s7",
    0b11000 => "s8",
    0b11001 => "s9",
    0b11010 => "s10",
    0b11011 => "s11",
    0b11100 => "t3",
    0b11101 => "t4",
    0b11110 => "t5",
    0b11111 => "t6"
  }
}

overload to_str = {reg_name_abi}

/* mappings for assembly */

val reg_name : bits(5) <-> string
mapping reg_name = {
    0b00000 <-> "zero",
    0b00001 <-> "ra",
    0b00010 <-> "sp",
    0b00011 <-> "gp",
    0b00100 <-> "tp",
    0b00101 <-> "t0",
    0b00110 <-> "t1",
    0b00111 <-> "t2",
    0b01000 <-> "fp",
    0b01001 <-> "s1",
    0b01010 <-> "a0",
    0b01011 <-> "a1",
    0b01100 <-> "a2",
    0b01101 <-> "a3",
    0b01110 <-> "a4",
    0b01111 <-> "a5",
    0b10000 <-> "a6",
    0b10001 <-> "a7",
    0b10010 <-> "s2",
    0b10011 <-> "s3",
    0b10100 <-> "s4",
    0b10101 <-> "s5",
    0b10110 <-> "s6",
    0b10111 <-> "s7",
    0b11000 <-> "s8",
    0b11001 <-> "s9",
    0b11010 <-> "s10",
    0b11011 <-> "s11",
    0b11100 <-> "t3",
    0b11101 <-> "t4",
    0b11110 <-> "t5",
    0b11111 <-> "t6"
}

mapping creg_name : bits(3) <-> string = {
  0b000 <-> "s0",
  0b001 <-> "s1",
  0b010 <-> "a0",
  0b011 <-> "a1",
  0b100 <-> "a2",
  0b101 <-> "a3",
  0b110 <-> "a4",
  0b111 <-> "a5"
}

val init_base_regs : unit -> unit
function init_base_regs () = {
  x1  = zero_reg;
  x2  = zero_reg;
  x3  = zero_reg;
  x4  = zero_reg;
  x5  = zero_reg;
  x6  = zero_reg;
  x7  = zero_reg;
  x8  = zero_reg;
  x9  = zero_reg;
  x10 = zero_reg;
  x11 = zero_reg;
  x12 = zero_reg;
  x13 = zero_reg;
  x14 = zero_reg;
  x15 = zero_reg;
  x15 = zero_reg;
  x16 = zero_reg;
  x17 = zero_reg;
  x18 = zero_reg;
  x19 = zero_reg;
  x20 = zero_reg;
  x21 = zero_reg;
  x22 = zero_reg;
  x23 = zero_reg;
  x24 = zero_reg;
  x25 = zero_reg;
  x26 = zero_reg;
  x27 = zero_reg;
  x28 = zero_reg;
  x29 = zero_reg;
  x30 = zero_reg;
  x31 = zero_reg
}
