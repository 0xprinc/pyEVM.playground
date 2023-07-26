# SHANGHAI FORK

import json
import os
from eth_hash.auto import keccak
import copy
from lib import Account, ethereum, Context, OpcodeResponse, OpcodeData, Stack, Memory, Storage
from lib import unsigned_to_signed, signed_to_unsigned
from lib import UINT256MAX, STATICCALL_DISALLOWED_OPCODES

# import keyboard
# def next_iteration():
#     while True:
#         event = keyboard.read_event(suppress=True)
#         if event.event_type == keyboard.KEY_DOWN and event.name == "right":
#             break

def highlight(string, index):
    highlighted_character = string[2*index]+string[2*index+1]
    highlighted_character = f"\033[46m{highlighted_character}"
    highlighted_character += "\033[0m"
    highlighted_string = string[:2*index] + highlighted_character + string[2*index + 2:]
    return highlighted_string

def get_char():
    # Set the terminal in raw mode
    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    try:
        tty.setraw(sys.stdin.fileno())
        # Read a single character from stdin
        ch = sys.stdin.read(1)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
    return ch


def opcodeStop(context, info):
    return OpcodeResponse(success=True, encounteredStop=True,returnData=None)
def opcodePush0(context, info):
    context.stack.push(0)
    return OpcodeResponse(success=True, encounteredStop=False,returnData=None) 
def opcodePush(context, info, numericPartOfName):
    data = 0
    for i in range(numericPartOfName):
        data = (data << 8) | context.code[context.pc + 1]
        context.pc += 1
    context.stack.push(data)
    return OpcodeResponse(success=True, encounteredStop=False,returnData=None)
def opcodePop(context, info):
    data = context.stack.pop()
    return OpcodeResponse(success=True, encounteredStop=False,returnData=None)
def opcodeAdd(context, info):
    a = context.stack.pop()
    b = context.stack.pop()
    result = (a + b)
    # overflow condition
    result &= UINT256MAX
    context.stack.push(result)
    return OpcodeResponse(success=True, encounteredStop=False,returnData=None)
def opcodeMul(context, info):
    a = context.stack.pop()
    b = context.stack.pop()
    result = (a * b)
    # overflow condition
    result &= UINT256MAX
    context.stack.push(result)
    return OpcodeResponse(success=True, encounteredStop=False,returnData=None)
def opcodeSub(context, info):
    a = context.stack.pop()
    b = context.stack.pop()
    result = (a - b)
    result &= UINT256MAX
    context.stack.push(result)
    return OpcodeResponse(success=True, encounteredStop=False,returnData=None)
def opcodeDiv(context, info):
    a = context.stack.pop()
    b = context.stack.pop()
    # Handle Divide by 0
    if b == 0:
        result = 0
    else:
        result = int(a / b)
    context.stack.push(result)
    return OpcodeResponse(success=True, encounteredStop=False,returnData=None)
def opcodeMod(context, info):
    a = context.stack.pop()
    b = context.stack.pop()
    if b == 0:
        result = 0
    else:
        result = a % b
    context.stack.push(result)
    return OpcodeResponse(success=True, encounteredStop=False,returnData=None)
def opcodeAddMod(context, info):
    a = context.stack.pop()
    b = context.stack.pop()
    result = a + b
    c = context.stack.pop()
    result = result % c
    result &= UINT256MAX
    context.stack.push(result)
    return OpcodeResponse(success=True, encounteredStop=False,returnData=None)
def opcodeMulMod(context, info):
    a = context.stack.pop()
    b = context.stack.pop()
    result = a * b
    c = context.stack.pop()
    result = result % c
    result &= UINT256MAX
    context.stack.push(result)
    return OpcodeResponse(success=True, encounteredStop=False,returnData=None)
def opcodeExp(context, info):
    a = context.stack.pop()
    exponent = context.stack.pop()
    result = a ** exponent
    result &= UINT256MAX
    context.stack.push(result)
    return OpcodeResponse(success=True, encounteredStop=False,returnData=None)
def opcodeSignExtend(context, info):
    a = context.stack.pop()
    b = context.stack.pop()
    b = b & ((1 << (a + 1) * 8) - 1)
    if (b >> ((a + 1) * 8 - 1)) != 0:
        mask = UINT256MAX ^ ((1 << (a + 1) * 8) - 1)
        b = b | mask
    context.stack.push(b)
    return OpcodeResponse(success=True, encounteredStop=False,returnData=None)
def opcodeSDiv(context, info):
    a = unsigned_to_signed(context.stack.pop())
    b = unsigned_to_signed(context.stack.pop())
    context.stack.push(signed_to_unsigned(a // b) if b != 0 else 0)
    return OpcodeResponse(success=True, encounteredStop=False,returnData=None)
def opcodeSMod(context, info):
    a = unsigned_to_signed(context.stack.pop())
    b = unsigned_to_signed(context.stack.pop())
    context.stack.push(signed_to_unsigned(a % b) if b != 0 else 0)
    return OpcodeResponse(success=True, encounteredStop=False,returnData=None)
def opcodeLT(context, info):
    a = context.stack.pop()
    b = context.stack.pop()
    context.stack.push(1 if a < b else 0)
    return OpcodeResponse(success=True, encounteredStop=False,returnData=None)
def opcodeGT(context, info):
    a = context.stack.pop()
    b = context.stack.pop()
    context.stack.push(1 if a > b else 0)
    return OpcodeResponse(success=True, encounteredStop=False,returnData=None)
def opcodeSLT(context, info):
    a = unsigned_to_signed(context.stack.pop())
    b = unsigned_to_signed(context.stack.pop())
    context.stack.push(1 if a < b else 0)
    return OpcodeResponse(success=True, encounteredStop=False,returnData=None)
def opcodeSGT(context, info):
    a = unsigned_to_signed(context.stack.pop())
    b = unsigned_to_signed(context.stack.pop())
    context.stack.push(1 if a > b else 0)
    return OpcodeResponse(success=True, encounteredStop=False,returnData=None)
def opcodeEQ(context, info):
    context.stack.push(1 if context.stack.pop() == context.stack.pop() else 0)
    return OpcodeResponse(success=True, encounteredStop=False,returnData=None)
def opcodeIsZero(context, info):
    context.stack.push(1 if context.stack.pop() == 0 else 0)
    return OpcodeResponse(success=True, encounteredStop=False,returnData=None)
def opcodeAnd(context, info):
    context.stack.push((context.stack.pop() & context.stack.pop()))
    return OpcodeResponse(success=True, encounteredStop=False,returnData=None)
def opcodeOR(context, info):
    context.stack.push((context.stack.pop() | context.stack.pop()))
    return OpcodeResponse(success=True, encounteredStop=False,returnData=None)
def opcodeXOR(context, info):
    context.stack.push((context.stack.pop() ^ context.stack.pop()))
    return OpcodeResponse(success=True, encounteredStop=False,returnData=None)
def opcodeNot(context, info):
    context.stack.push(UINT256MAX ^ context.stack.pop())
    return OpcodeResponse(success=True, encounteredStop=False,returnData=None)
def opcodeSHL(context, info):
    a = context.stack.pop()
    b = context.stack.pop()
    context.stack.push(0 if a >= 256 else ((b << a) % 2 ** 256))
    return OpcodeResponse(success=True, encounteredStop=False,returnData=None)
def opcodeSHR(context, info):
    a = context.stack.pop()
    b = context.stack.pop()
    context.stack.push(b >> a)
    return OpcodeResponse(success=True, encounteredStop=False,returnData=None)
def opcodeSAR(context, info):
    shift, signed_value = context.stack.pop(), unsigned_to_signed(context.stack.pop())
    context.stack.push(signed_to_unsigned(signed_value >> shift))
    return OpcodeResponse(success=True, encounteredStop=False,returnData=None)
def opcodeByte(context, info):
    offset, value = context.stack.pop(), context.stack.pop()
    if offset < 32:
        context.stack.push((value >> ((31 - offset) * 8)) & 0xFF)
    else:
        context.stack.push(0)
    return OpcodeResponse(success=True, encounteredStop=False,returnData=None)
def opcodeDup(context, info, numericPartOfName):
    a = context.stack.access_at_index(numericPartOfName * -1)
    context.stack.push(a)
    return OpcodeResponse(success=True, encounteredStop=False,returnData=None)
def opcodeSwap(context, info, numericPartOfName):
    a = context.stack.access_at_index((numericPartOfName + 1) * -1)
    b = context.stack.pop()
    context.stack.push(a)
    context.stack.set_at_index((numericPartOfName + 1) * -1, b)
    return OpcodeResponse(success=True, encounteredStop=False,returnData=None)
def opcodeInvalid(context, info):
    return OpcodeResponse(success=False, encounteredStop=False,returnData=None)
def opcodePC(context, info):
    context.stack.push(context.pc)
    return OpcodeResponse(success=True, encounteredStop=False,returnData=None)
def opcodeGas(context, info):
    context.stack.push(UINT256MAX)
    return OpcodeResponse(success=True, encounteredStop=False,returnData=None)
def opcodeJump(context, info):
    a = context.stack.pop()
    if a in context.valid_jumpdests_set:
        context.set_pc(a)
        return OpcodeResponse(success=True, encounteredStop=False,returnData=None)
    else:
        return OpcodeResponse(success=False, encounteredStop=False,returnData=None)
def opcodeJumpIf(context, info):
    a = context.stack.pop()
    b = context.stack.pop()
    if b == 0:
        return OpcodeResponse(success=True, encounteredStop=False,returnData=None)
    else:
        if a in context.valid_jumpdests_set:
            context.set_pc(a)
            return OpcodeResponse(
                success=True, encounteredStop=False,returnData=None)
        else:
            return OpcodeResponse(
                success=False,
                encounteredStop=False,
                data=None)
def opcodeJumpDest(context, info):
    return OpcodeResponse(success=True, encounteredStop=False,returnData=None)
def opcodeMLoad(context, info):
    a = context.stack.pop()
    b = int(context.memory.load(a, 32).hex(), 16)
    context.stack.push(b)
    return OpcodeResponse(success=True, encounteredStop=False,returnData=None)
def opcodeMStore(context, info):
    a = context.stack.pop()
    b = hex(context.stack.pop())[2:]
    if len(b) % 2 == 1:
        b = "0" + b
    b = bytes.fromhex(b)

    size = len(b)
    b = bytes(32 - size) + b

    context.memory.store(a, b)
    return OpcodeResponse(success=True, encounteredStop=False,returnData=None)
def opcodeMStore8(context, info):
    a = context.stack.pop()
    b = hex(context.stack.pop())[2:]
    if len(b) % 2 == 1:
        b = "0" + b
    b = bytes.fromhex(b)

    size = len(b)

    if size == 1:
        context.memory.store(a, b)
        return OpcodeResponse(success=True, encounteredStop=False,returnData=None)
    else:
        return OpcodeResponse(success=False, encounteredStop=False,returnData=None)
def opcodeMSize(context, info):
    context.stack.push(context.memory.msize())
    return OpcodeResponse(success=True, encounteredStop=False,returnData=None)
def opcodeSHA3(context, info):
    a = context.stack.pop()
    b = context.stack.pop()
    c = context.memory.load(a, b)
    context.stack.push(int(keccak(bytes(c)).hex(), 16))
    return OpcodeResponse(success=True, encounteredStop=False,returnData=None)
def opcodeAddress(context, info):
    a = int(info["tx"]["to"], 16)
    context.stack.push(a)
    return OpcodeResponse(success=True, encounteredStop=False,returnData=None)
def opcodeCaller(context, info):
    a = int(info["tx"]["from"], 16)
    context.stack.push(a)
    return OpcodeResponse(success=True, encounteredStop=False,returnData=None)
def opcodeOrigin(context, info):
    a = int(info["tx"]["origin"], 16)
    context.stack.push(a)
    return OpcodeResponse(success=True, encounteredStop=False,returnData=None)
def opcodeGasPrice(context, info):
    a = int(info["tx"]["gasprice"], 16)
    context.stack.push(a)
    return OpcodeResponse(success=True, encounteredStop=False,returnData=None)
def opcodeBaseFee(context, info):
    a = int(info["block"]["basefee"], 16)
    context.stack.push(a)
    return OpcodeResponse(success=True, encounteredStop=False,returnData=None)
def opcodeCoinBase(context, info):
    a = int(info["block"]["coinbase"], 16)
    context.stack.push(a)
    return OpcodeResponse(success=True, encounteredStop=False,returnData=None)
def opcodeTimeStamp(context, info):
    a = int(info["block"]["timestamp"], 16)
    context.stack.push(a)
    return OpcodeResponse(success=True, encounteredStop=False,returnData=None)
def opcodeNumber(context, info):
    a = int(info["block"]["number"], 16)
    context.stack.push(a)
    return OpcodeResponse(success=True, encounteredStop=False,returnData=None)
def opcodeDifficulty(context, info):
    a = int(info["block"]["difficulty"], 16)
    context.stack.push(a)
    return OpcodeResponse(success=True, encounteredStop=False,returnData=None)
def opcodeGasLimit(context, info):
    a = int(info["block"]["gaslimit"], 16)
    context.stack.push(a)
    return OpcodeResponse(success=True, encounteredStop=False,returnData=None)
def opcodeChainId(context, info):
    a = int(info["block"]["chainid"], 16)
    context.stack.push(a)
    return OpcodeResponse(success=True, encounteredStop=False,returnData=None)
def opcodeBlockHash(context, info):
    context.stack.push(0x0)
    return OpcodeResponse(success=True, encounteredStop=False,returnData=None)
def opcodeBalance(context, info):
    a = context.stack.pop()
    if not context.world_state.get(a):
        context.stack.push(0)
    else:

        b = context.world_state.get(a).getBalance()
        context.stack.push(b)

    return OpcodeResponse(success=True, encounteredStop=False,returnData=None)
def opcodeCallValue(context, info):
    a = int(info["tx"]["value"], 16)
    context.stack.push(a)
    return OpcodeResponse(success=True, encounteredStop=False,returnData=None)
def opcodeCallDataLoad(context, info):
    a = context.stack.pop()
    b = int(context.calldata.load(a, 32).hex(), 16)
    context.stack.push(b)
    return OpcodeResponse(success=True, encounteredStop=False,returnData=None)
def opcodeCallDataSize(context, info):
    a = context.calldata.size()
    context.stack.push(a)
    return OpcodeResponse(success=True, encounteredStop=False,returnData=None)
def opcodeCallDataCopy(context, info):
    a = context.stack.pop()
    b = context.stack.pop()
    c = context.stack.pop()
    calldata = context.calldata.load(b, c)
    context.memory.store(a, calldata)
    return OpcodeResponse(success=True, encounteredStop=False,returnData=None)
def opcodeCodeSize(context, info):
    a = len(context.code)
    context.stack.push(a)
    return OpcodeResponse(success=True, encounteredStop=False,returnData=None)
def opcodeCodeCopy(context, info):
    a = context.stack.pop()
    b = context.stack.pop()
    c = context.stack.pop()
    size = len(context.code)
    code = bytearray(context.code)
    if b + c > size:
        code.extend(bytes((b + c) - size))

    context.memory.store(a, code[b:b + c])
    return OpcodeResponse(success=True, encounteredStop=False,returnData=None)
def opcodeExtCodeSize(context, info):
    a = context.stack.pop()
    if not context.world_state.get(a):
        context.stack.push(0)
    else:
        context.stack.push(len(context.world_state.get(a).code))
    return OpcodeResponse(success=True, encounteredStop=False,returnData=None)
def opcodeExtCodeCopy(context, info):
    a = context.stack.pop()
    b = context.stack.pop()
    c = context.stack.pop()
    d = context.stack.pop()
    if not context.world_state.get(a):
        context.memory.store(b, bytes())
    else:
        size = len(context.world_state.get(a).code)
        code = bytearray(context.world_state.get(a).code)
        if c + d > size:
            code.extend(bytes((c + d) - size))
        context.memory.store(b, code[c:c + d])
    return OpcodeResponse(success=True, encounteredStop=False,returnData=None)
def opcodeExtCodeHash(context, info):
    a = context.stack.pop()
    if not context.world_state.get(a):
        context.stack.push(0)
    else:
        code = bytearray(context.world_state.get(a).code)
        context.stack.push(int(keccak(bytes(code)).hex(), 16))
    return OpcodeResponse(success=True, encounteredStop=False,returnData=None)
def opcodeSelfBalance(context, info):
    a = int(info["tx"]["to"], 16)
    if not context.world_state.get(a):
        context.stack.push(0)
    else:
        b = context.world_state.get(a).getBalance()
        context.stack.push(b)
    return OpcodeResponse(success=True, encounteredStop=False,returnData=None)
def opcodeSStore(context, info):
    a = context.stack.pop()
    b = context.stack.pop()
    context.storage.store(a, b)
    return OpcodeResponse(success=True, encounteredStop=False,returnData=None)
def opcodeSLoad(context, info):
    a = context.stack.pop()
    b = context.storage.load(a)
    context.stack.push(b)
    return OpcodeResponse(success=True, encounteredStop=False,returnData=None)
def opcodeLog(context, info, numericPartOfName):
    a = context.stack.pop()
    b = context.stack.pop()
    c = int(context.memory.load(a, b).hex(), 16)
    log = {}
    log["address"] = int(info["tx"]["to"], 16)
    log["data"] = c
    log["topics"] = []
    for i in range(numericPartOfName):
        log["topics"].append(context.stack.pop())
    context.logs.append(log)
    return OpcodeResponse(success=True, encounteredStop=False,returnData=None)
def opcodeReturn(context, info):
    a = context.stack.pop()
    b = context.stack.pop()
    c = int(context.memory.load(a, b).hex(), 16)
    d = context.memory.load(a, b)
    context.returndata.data = d
    return OpcodeResponse(success=True, encounteredStop=False,returnData=c)
def opcodeRevert(context, info):
    a = context.stack.pop()
    b = context.stack.pop()
    c = int(context.memory.load(a, b).hex(), 16)
    d = context.memory.load(a, b)
    return OpcodeResponse(success=False, encounteredStop=False,returnData=c)
def opcodeCall(context, info):
    gas = context.stack.pop()
    address = context.stack.pop()
    value = context.stack.pop()
    if info["isStaticCall"] and value != 0:
        return OpcodeResponse(success=False, encounteredStop=False,returnData=None)
    argOffset = context.stack.pop()
    argSize = context.stack.pop()
    retOffset = context.stack.pop()
    retSize = context.stack.pop()
    new_info = copy.deepcopy(info)

    if info.get("tx") and info.get("tx").get("to"):
        new_info["tx"]["from"] = str(info["tx"]["to"])
    if new_info.get("tx"):
        new_info["tx"]["to"] = hex(address)[2:]
    else:
        new_info["tx"] = {"to": hex(address)[2:]}

    code = context.world_state.get(address).code
    (success, stack, logs, returndata, after_execution_world_state) = evm(
        code = code, info = new_info, outputStackLen = 0, isStaticCall = False)

    if success:
        context.world_state = after_execution_world_state

    if returndata:
        returndata = hex(returndata)[2:]
        if len(returndata) % 2 == 1:
            returndata = "0" + returndata

        returndata = returndata[:retSize * 2]
        returndata = bytearray.fromhex(returndata)

        context.returndata.setreturndata(returndata)
        context.memory.store(retOffset, returndata)
    context.stack.push(int(success))
    return OpcodeResponse(success=True, encounteredStop=False,returnData=None)
def opcodeReturnDataSize(context, info):
    a = context.returndata.size()
    context.stack.push(a)
    return OpcodeResponse(success=True, encounteredStop=False,returnData=None)
def opcodeReturnDataCopy(context, info):
    a = context.stack.pop()
    b = context.stack.pop()
    c = context.stack.pop()
    returndata = context.returndata.load(b, c)
    context.memory.store(a, returndata)
    return OpcodeResponse(success=True, encounteredStop=False,returnData=None)
def opcodeDelegateCall(context, info):
    gas = context.stack.pop()
    address = context.stack.pop()
    argOffset = context.stack.pop()
    argSize = context.stack.pop()
    retOffset = context.stack.pop()
    retSize = context.stack.pop()
    new_info = copy.deepcopy(info)

    code = context.world_state.get(address).code
    (success, stack, logs, returndata, after_execution_world_state) = evm(
        code = code, info = new_info, outputStackLen = 0, isStaticCall = False)

    if success:
        context.world_state = after_execution_world_state

    if returndata:
        returndata = hex(returndata)[2:]
        if len(returndata) % 2 == 1:
            returndata = "0" + returndata

        returndata = returndata[:retSize * 2]
        returndata = bytearray.fromhex(returndata)

        context.returndata.setreturndata(returndata)
        context.memory.store(retOffset, returndata)
    context.stack.push(int(success))
    return OpcodeResponse(success=True, encounteredStop=False,returnData=None)
def opcodeStaticCall(context, info):
    gas = context.stack.pop()
    address = context.stack.pop()
    argOffset = context.stack.pop()
    argSize = context.stack.pop()
    retOffset = context.stack.pop()
    retSize = context.stack.pop()
    new_info = copy.deepcopy(info)

    if info.get("tx") and info.get("tx").get("to"):
        new_info["tx"]["from"] = str(info["tx"]["to"])
    if new_info.get("tx"):
        new_info["tx"]["to"] = hex(address)[2:]
    else:
        new_info["tx"] = {"to": hex(address)[2:]}

    code = context.world_state.get(address).code
    (success, stack, logs, returndata, after_execution_world_state) = evm(
        code = code, info = new_info, outputStackLen = 0, isStaticCall = True)

    if success:
        context.world_state = after_execution_world_state
    if returndata:
        returndata = hex(returndata)[2:]
        if len(returndata) % 2 == 1:
            returndata = "0" + returndata

        returndata = returndata[:retSize * 2]
        returndata = bytearray.fromhex(returndata)

        context.returndata.setreturndata(returndata)
        context.memory.store(retOffset, returndata)
    context.stack.push(int(success))
    return OpcodeResponse(success=True, encounteredStop=False,returnData=None)
def opcodeCreate(context, info):
    value = context.stack.pop()
    offset = context.stack.pop()
    size = context.stack.pop()

    current_address = info["tx"]["to"][2:]
    if context.world_state.get(current_address):
        nonce = context.world_state.get(current_address).nonce
    else:
        nonce = 0
    current_address = bytes.fromhex(current_address)

    nonce = hex(nonce)[2:]
    if len(nonce) % 2 == 1:
        nonce = "0" + nonce
    nonce = bytes.fromhex(nonce)
    contract_address = int(
        keccak(
            bytes(
                current_address +
                nonce)).hex(),
        16)

    code = context.memory.load(offset, size)
    (success, stack, logs, returndata, after_execution_world_state) = evm(
        code = code, info = info, outputStackLen = 0, isStaticCall = False)

    if not success:
        context.stack.push(0)
        return OpcodeResponse(success=True, encounteredStop=False,returnData=None)

    if not returndata:
        returndata = bytes()
    else:
        returndata = bytes.fromhex(hex(returndata)[2:])

    context.world_state.set(
        contract_address,
        Account(
            balance=value,
            code=returndata))
    context.stack.push(contract_address)
    return OpcodeResponse(success=True, encounteredStop=False,returnData=None)
def opcodeSelfDestruct(context, info):
    a = context.stack.pop()
    current_address = int(info["tx"]["to"], 16)

    if context.world_state.get(a):
        context.world_state.get(
            a).balance += context.world_state.get(current_address).balance
    else:
        context.world_state.set(
            a, Account(
                balance=context.world_state.get(current_address).balance))

    context.world_state.get(current_address).balance = 0
    context.world_state.get(current_address).code = bytes()
    return OpcodeResponse(success=True, encounteredStop=False,returnData=None)


opcode = {}
def hello():
    opcode[0x00] = OpcodeData(0x00, "STOP", opcodeStop)
    opcode[0x5F] = OpcodeData(0x5F, "PUSH0", opcodePush0)
    opcode[0x60] = OpcodeData(0x60, "PUSH1", opcodePush, 1)
    opcode[0x61] = OpcodeData(0x61, "PUSH2", opcodePush, 2)
    opcode[0x62] = OpcodeData(0x62, "PUSH3", opcodePush, 3)
    opcode[0x63] = OpcodeData(0x63, "PUSH4", opcodePush, 4)
    opcode[0x64] = OpcodeData(0x64, "PUSH5", opcodePush, 5)
    opcode[0x65] = OpcodeData(0x65, "PUSH6", opcodePush, 6)
    opcode[0x66] = OpcodeData(0x66, "PUSH7", opcodePush, 7)
    opcode[0x67] = OpcodeData(0x67, "PUSH8", opcodePush, 8)
    opcode[0x68] = OpcodeData(0x68, "PUSH9", opcodePush, 9)
    opcode[0x69] = OpcodeData(0x69, "PUSH10", opcodePush, 10)
    opcode[0x6A] = OpcodeData(0x6A, "PUSH11", opcodePush, 11)
    opcode[0x6B] = OpcodeData(0x6B, "PUSH12", opcodePush, 12)
    opcode[0x6C] = OpcodeData(0x6C, "PUSH13", opcodePush, 13)
    opcode[0x6D] = OpcodeData(0x6D, "PUSH14", opcodePush, 14)
    opcode[0x6E] = OpcodeData(0x6E, "PUSH15", opcodePush, 15)
    opcode[0x6F] = OpcodeData(0x6F, "PUSH16", opcodePush, 16)
    opcode[0x70] = OpcodeData(0x70, "PUSH17", opcodePush, 17)
    opcode[0x71] = OpcodeData(0x71, "PUSH18", opcodePush, 18)
    opcode[0x72] = OpcodeData(0x72, "PUSH19", opcodePush, 19)
    opcode[0x73] = OpcodeData(0x73, "PUSH20", opcodePush, 20)
    opcode[0x74] = OpcodeData(0x74, "PUSH21", opcodePush, 21)
    opcode[0x75] = OpcodeData(0x75, "PUSH22", opcodePush, 22)
    opcode[0x76] = OpcodeData(0x76, "PUSH23", opcodePush, 23)
    opcode[0x77] = OpcodeData(0x77, "PUSH24", opcodePush, 24)
    opcode[0x78] = OpcodeData(0x78, "PUSH25", opcodePush, 25)
    opcode[0x79] = OpcodeData(0x79, "PUSH26", opcodePush, 26)
    opcode[0x7A] = OpcodeData(0x7A, "PUSH27", opcodePush, 27)
    opcode[0x7B] = OpcodeData(0x7B, "PUSH28", opcodePush, 28)
    opcode[0x7C] = OpcodeData(0x7C, "PUSH29", opcodePush, 29)
    opcode[0x7D] = OpcodeData(0x7D, "PUSH30", opcodePush, 30)
    opcode[0x7E] = OpcodeData(0x7E, "PUSH31", opcodePush, 31)
    opcode[0x7F] = OpcodeData(0x7F, "PUSH32", opcodePush, 32)
    opcode[0x50] = OpcodeData(0x50, "POP", opcodePop)
    opcode[0x01] = OpcodeData(0x01, "ADD", opcodeAdd)
    opcode[0x02] = OpcodeData(0x02, "MUL", opcodeMul)
    opcode[0x03] = OpcodeData(0x03, "SUB", opcodeSub)
    opcode[0x04] = OpcodeData(0x04, "DIV", opcodeDiv)
    opcode[0x06] = OpcodeData(0x06, "MOD", opcodeMod)
    opcode[0x08] = OpcodeData(0x08, "MODADD", opcodeAddMod)
    opcode[0x09] = OpcodeData(0x09, "MODMUL", opcodeMulMod)
    opcode[0x0a] = OpcodeData(0xa, "EXP", opcodeExp)
    opcode[0x0b] = OpcodeData(0xa, "SIGNEXTEND", opcodeSignExtend)
    opcode[0x05] = OpcodeData(0x5, "SDIV", opcodeSDiv)
    opcode[0x07] = OpcodeData(0x7, "SMOD", opcodeSMod)
    opcode[0x10] = OpcodeData(0x10, "LT", opcodeLT)
    opcode[0x11] = OpcodeData(0x11, "GT", opcodeGT)
    opcode[0x12] = OpcodeData(0x12, "SLT", opcodeSLT)
    opcode[0x13] = OpcodeData(0x13, "SGT", opcodeSGT)
    opcode[0x14] = OpcodeData(0x14, "EQ", opcodeEQ)
    opcode[0x15] = OpcodeData(0x15, "ISZERO", opcodeIsZero)
    opcode[0x16] = OpcodeData(0x16, "AND", opcodeAnd)
    opcode[0x17] = OpcodeData(0x17, "OR", opcodeOR)
    opcode[0x18] = OpcodeData(0x18, "XOR", opcodeXOR)
    opcode[0x19] = OpcodeData(0x19, "NOT", opcodeNot)
    opcode[0x1b] = OpcodeData(0x1b, "SHL", opcodeSHL)
    opcode[0x1c] = OpcodeData(0x1c, "SHR", opcodeSHR)
    opcode[0x1d] = OpcodeData(0x1d, "SAR", opcodeSAR)
    opcode[0x1a] = OpcodeData(0x1a, "BYTE", opcodeByte)
    opcode[0x80] = OpcodeData(0x80, "DUP1", opcodeDup, 1)
    opcode[0x81] = OpcodeData(0x81, "DUP2", opcodeDup, 2)
    opcode[0x82] = OpcodeData(0x82, "DUP3", opcodeDup, 3)
    opcode[0x83] = OpcodeData(0x83, "DUP4", opcodeDup, 4)
    opcode[0x84] = OpcodeData(0x84, "DUP5", opcodeDup, 5)
    opcode[0x85] = OpcodeData(0x85, "DUP6", opcodeDup, 6)
    opcode[0x86] = OpcodeData(0x86, "DUP7", opcodeDup, 7)
    opcode[0x87] = OpcodeData(0x87, "DUP8", opcodeDup, 8)
    opcode[0x88] = OpcodeData(0x88, "DUP9", opcodeDup, 9)
    opcode[0x89] = OpcodeData(0x89, "DUP10", opcodeDup, 10)
    opcode[0x8A] = OpcodeData(0x8A, "DUP11", opcodeDup, 11)
    opcode[0x8B] = OpcodeData(0x8B, "DUP12", opcodeDup, 12)
    opcode[0x8C] = OpcodeData(0x8C, "DUP13", opcodeDup, 13)
    opcode[0x8D] = OpcodeData(0x8D, "DUP14", opcodeDup, 14)
    opcode[0x8E] = OpcodeData(0x8E, "DUP15", opcodeDup, 15)
    opcode[0x8F] = OpcodeData(0x8F, "DUP16", opcodeDup, 16)
    opcode[0x90] = OpcodeData(0x90, "SWAP1", opcodeSwap, 1)
    opcode[0x91] = OpcodeData(0x91, "SWAP2", opcodeSwap, 2)
    opcode[0x92] = OpcodeData(0x92, "SWAP3", opcodeSwap, 3)
    opcode[0x93] = OpcodeData(0x93, "SWAP4", opcodeSwap, 4)
    opcode[0x94] = OpcodeData(0x94, "SWAP5", opcodeSwap, 5)
    opcode[0x95] = OpcodeData(0x95, "SWAP6", opcodeSwap, 6)
    opcode[0x96] = OpcodeData(0x96, "SWAP7", opcodeSwap, 7)
    opcode[0x97] = OpcodeData(0x97, "SWAP8", opcodeSwap, 8)
    opcode[0x98] = OpcodeData(0x98, "SWAP9", opcodeSwap, 9)
    opcode[0x99] = OpcodeData(0x99, "SWAP10", opcodeSwap, 10)
    opcode[0x9A] = OpcodeData(0x9A, "SWAP11", opcodeSwap, 11)
    opcode[0x9B] = OpcodeData(0x9B, "SWAP12", opcodeSwap, 12)
    opcode[0x9C] = OpcodeData(0x9C, "SWAP13", opcodeSwap, 13)
    opcode[0x9D] = OpcodeData(0x9D, "SWAP14", opcodeSwap, 14)
    opcode[0x9E] = OpcodeData(0x9E, "SWAP15", opcodeSwap, 15)
    opcode[0x9F] = OpcodeData(0x9F, "SWAP16", opcodeSwap, 16)
    opcode[0xfe] = OpcodeData(0xfe, "INVALID", opcodeInvalid)
    opcode[0x58] = OpcodeData(0x58, "PC", opcodePC)
    opcode[0x5a] = OpcodeData(0x5a, "GAS", opcodeGas)
    opcode[0x56] = OpcodeData(0x56, "JUMP", opcodeJump)
    opcode[0x57] = OpcodeData(0x57, "JUMPI", opcodeJumpIf)
    opcode[0x5b] = OpcodeData(0x5b, "JUMPDEST", opcodeJumpDest)
    opcode[0x51] = OpcodeData(0x51, "MLOAD", opcodeMLoad)
    opcode[0x52] = OpcodeData(0x52, "MSTORE", opcodeMStore)
    opcode[0x53] = OpcodeData(0x53, "MSTORE8", opcodeMStore8)
    opcode[0x59] = OpcodeData(0x59, "MSIZE", opcodeMSize)
    opcode[0x20] = OpcodeData(0x20, "SHA3", opcodeSHA3)
    opcode[0x30] = OpcodeData(0x30, "ADDRESS", opcodeAddress)
    opcode[0x33] = OpcodeData(0x33, "CALLER", opcodeCaller)
    opcode[0x32] = OpcodeData(0x32, "ORIGIN", opcodeOrigin)
    opcode[0x3a] = OpcodeData(0x99, "GASPRICE", opcodeGasPrice)
    opcode[0x48] = OpcodeData(0x48, "BASEFEE", opcodeBaseFee)
    opcode[0x41] = OpcodeData(0x41, "COINBASE", opcodeCoinBase)
    opcode[0x42] = OpcodeData(0x42, "TIMESTAMP", opcodeTimeStamp)
    opcode[0x43] = OpcodeData(0x43, "NUMBER", opcodeNumber)
    opcode[0x44] = OpcodeData(0x44, "DIFFICULTY", opcodeDifficulty)
    opcode[0x45] = OpcodeData(0x45, "GASLIMIT", opcodeGasLimit)
    opcode[0x46] = OpcodeData(0x46, "CHAINID", opcodeChainId)
    opcode[0x40] = OpcodeData(0x40, "BLOCKHASH", opcodeBlockHash)
    opcode[0x31] = OpcodeData(0x31, "BALANCE", opcodeBalance)
    opcode[0x34] = OpcodeData(0x34, "CALLVALUE", opcodeCallValue)
    opcode[0x35] = OpcodeData(0x35, "CALLDATALOAD", opcodeCallDataLoad)
    opcode[0x36] = OpcodeData(0x36, "CALLDATASIZE", opcodeCallDataSize)
    opcode[0x37] = OpcodeData(0x37, "CALLDATACOPY", opcodeCallDataCopy)
    opcode[0x38] = OpcodeData(0x38, "CODESIZE", opcodeCodeSize)
    opcode[0x39] = OpcodeData(0x39, "CODECOPY", opcodeCodeCopy)
    opcode[0x3b] = OpcodeData(0x3b, "EXTCODESIZE", opcodeExtCodeSize)
    opcode[0x3c] = OpcodeData(0x3c, "EXTCODECOPY", opcodeExtCodeCopy)
    opcode[0x3f] = OpcodeData(0x3f, "EXTCODEHASH", opcodeExtCodeHash)
    opcode[0x47] = OpcodeData(0x47, "SELFBALANCE", opcodeSelfBalance)
    opcode[0x54] = OpcodeData(0x54, "SLOAD", opcodeSLoad)
    opcode[0x55] = OpcodeData(0x55, "SSTORE", opcodeSStore)
    opcode[0xa0] = OpcodeData(0xa0, "LOG0", opcodeLog, 0)
    opcode[0xa1] = OpcodeData(0xa1, "LOG1", opcodeLog, 1)
    opcode[0xa2] = OpcodeData(0xa2, "LOG2", opcodeLog, 2)
    opcode[0xa3] = OpcodeData(0xa3, "LOG3", opcodeLog, 3)
    opcode[0xa4] = OpcodeData(0xa4, "LOG4", opcodeLog, 4)
    opcode[0xf3] = OpcodeData(0xf3, "RETURN", opcodeReturn)
    opcode[0xfd] = OpcodeData(0xfd, "REVERT", opcodeRevert)
    opcode[0xf1] = OpcodeData(0xf1, "CALL", opcodeCall)
    opcode[0x3d] = OpcodeData(0x3d, "RETURNDATASIZE", opcodeReturnDataSize)
    opcode[0x3e] = OpcodeData(0x3e, "RETURNDATACOPY", opcodeReturnDataCopy)
    opcode[0xf4] = OpcodeData(0xf4, "DELEGATECALL", opcodeDelegateCall)
    opcode[0xfa] = OpcodeData(0xfa, "STATICCALL", opcodeStaticCall)
    opcode[0xf0] = OpcodeData(0xfa, "CREATE", opcodeCreate)
    opcode[0xff] = OpcodeData(0xff, "SELFDESTRUCT", opcodeSelfDestruct)
hello()

def evm(code, info):
    calldata = bytes()
    context = Context(world_state=ethereum(), code=code, calldata = calldata)

    while context.pc < len(code):
        opcodeReturn = OpcodeResponse(True, False, None)
        op = code[context.pc]
        if info["isStaticCall"]:
            info["isStaticCall"] = True
            if op in STATICCALL_DISALLOWED_OPCODES:
                opcodeReturn.success = False
                break
        opcodeObj = opcode.get(op)  # means opcode is present
        if opcodeObj:
            print(highlight(str(code.hex()), context.pc), end = "\n", flush = True)

            if opcodeObj.numericPartOfName is None:
                opcodeReturn = opcodeObj.run(context, info)
            else:
                opcodeReturn = opcodeObj.run(
                    context, info, opcodeObj.numericPartOfName)
            if opcodeReturn.encounteredStop:
                break
            if not opcodeReturn.success:
                break
        else:
            print("Opcode not found ", hex(op))
            return (True, [], [], None, ethereum())
        context.stack.represent()
        context.memory.represent()
        context.storage.represent()
        print("++++++++++")
        context.pc += 1
    logs = context.logs
    context.returndata.represent()
    if not opcodeReturn.success:
        return (opcodeReturn.success, logs, context.returndata, ethereum)
    return (opcodeReturn.success, logs, context.returndata, ethereum)


def test():
    script_dirname = os.path.dirname(os.path.abspath(__file__))
    json_file = os.path.join(script_dirname, "..", "test", "me.json")
    with open(json_file) as f:
        data = json.load(f)
        total = len(data)

        for i, test in enumerate(data):

            code = bytes.fromhex(test['code'])
            info = test
            expected_stack = []
            expected_return = None
            evm(code = code, info = info)



if __name__ == '__main__':
    test()
