const ffi = require('ffi-napi')
const ref = require('ref-napi')

const fs = require('fs')

const andgoMpc = ffi.DynamicLibrary('./andgo-mpc.so', ffi.RTLD_NOW)
const StartKeygenC = ffi.ForeignFunction(andgoMpc.get('StartKeygenC'), ref.types.CString, [ref.types.CString], ffi.FFI_STDCALL)
const ContKeygenC = ffi.ForeignFunction(andgoMpc.get('ContKeygenC'), ref.types.CString, [ref.types.CString], ffi.FFI_STDCALL)
const StartSignC = ffi.ForeignFunction(andgoMpc.get('StartSignC'), ref.types.CString, [ref.types.CString], ffi.FFI_STDCALL)
const ContSignC = ffi.ForeignFunction(andgoMpc.get('ContSignC'), ref.types.CString, [ref.types.CString], ffi.FFI_STDCALL)

const makeKeygenOptions = (participants, self, threshold, sessionId) => {
    return JSON.stringify({
        Participants: participants,
        Self: self,
        Threshold: threshold,
        SessionId: sessionId
    })
}
// Make options object for all participants. Only SelfID should be different.
let aliceOpts = makeKeygenOptions(["alice", "bob", "charlie"], "alice", 1, "dummySession")
let bobOpts = makeKeygenOptions(["alice", "bob", "charlie"], "bob", 1, "dummySession")
let charlieOpts = makeKeygenOptions(["alice", "bob", "charlie"], "charlie", 1, "dummySession")
//console.log("index.js: aliceOpts - ", aliceOpts)

const joinMessages = (msgs1, msgs2, msgs3, to) => {
    msgs = []
    if (msgs1 !== null) msgs.push(...msgs1)
    if (msgs2 !== null) msgs.push(...msgs2)
    if (msgs3 !== null) msgs.push(...msgs3)
    result = msgs.filter(msg => {
        return msg.From !== to && (msg.To === to || msg.To === "")
    })
    return result
}

// Get a ContKeygenResult(Handler, Config, AllReceived, Msgs)
let aliceRes, bobRes, charlieRes = null
let aliceContParams, bobContParams, charlieContParams = null
let aliceConfig, bobConfig, charlieConfig = null
keygen()
async function keygen() {
    await aliceKeygenStart()
    await bobKeygenStart()
    await charlieKeygenStart()
    await updateKParams()
    await aliceKeygenAdvance()
    await bobKeygenAdvance()
    await charlieKeygenAdvance()
    await updateKParams()
    await aliceKeygenAdvance()
    await bobKeygenAdvance()
    await charlieKeygenAdvance()
    await updateKParams()
    await aliceKeygenAdvance()
    await bobKeygenAdvance()
    await charlieKeygenAdvance()
    await updateKParams()
    await aliceKeygenAdvance()
    await bobKeygenAdvance()
    await charlieKeygenAdvance()
    console.log("Keygen Done")
    await sign()
}

async function aliceKeygenStart(printResult = false) {
    try {
        aliceRes = JSON.parse(StartKeygenC(aliceOpts))
        if (printResult) {
            console.log(JSON.stringify(aliceRes))
        }
    } catch (err) {
        console.log("index.js: ", err)
    }
    return
}

async function bobKeygenStart(printResult = false) {
    try {
        bobRes = JSON.parse(StartKeygenC(bobOpts))
        if (printResult) {
            console.log(JSON.stringify(bobRes))
        }
    } catch (err) {
        console.log("index.js: ", err)
    }
    return
}

async function charlieKeygenStart(printResult = false) {
    try {
        charlieRes = JSON.parse(StartKeygenC(charlieOpts))
        if (printResult) {
            console.log(JSON.stringify(charlieRes))
        }
    } catch (err) {
        console.log("index.js: ", err)
    }
    return
}

async function aliceKeygenAdvance(printResult = false) {
    aliceRes = JSON.parse(ContKeygenC(aliceContParams))
    if (aliceRes.Config !== undefined) {
        //console.log("Result: ", JSON.stringify(aliceRes.Config))
        aliceConfig = aliceRes.Config
        return
    }
    if (printResult) {
        console.log(JSON.stringify(aliceRes))
    }
}
async function bobKeygenAdvance(printResult = false) {
    bobRes = JSON.parse(ContKeygenC(bobContParams))
    if (bobRes.Config !== undefined) {
        //console.log("Result: ", JSON.stringify(bobRes.Config))
        bobConfig = bobRes.Config
        return
    }
    if (printResult) {
        console.log(JSON.stringify(bobRes))
    }
}
async function charlieKeygenAdvance(printResult = false) {
    charlieRes = JSON.parse(ContKeygenC(charlieContParams))
    if (charlieRes.Config !== undefined) {
        //console.log("Result: ", JSON.stringify(charlieRes.Config))
        charlieConfig = charlieRes.Config
        return
    }
    if (printResult) {
        console.log(JSON.stringify(charlieRes))
    }
}

async function updateKParams() {
    aliceContParams = JSON.stringify({
        Handler: aliceRes.Handler,
        Msgs: joinMessages(aliceRes.Msgs, bobRes.Msgs, charlieRes.Msgs, 'alice')
    })
    bobContParams = JSON.stringify({
        Handler: bobRes.Handler,
        Msgs: joinMessages(aliceRes.Msgs, bobRes.Msgs, charlieRes.Msgs, 'bob')
    })
    charlieContParams = JSON.stringify({
        Handler: charlieRes.Handler,
        Msgs: joinMessages(aliceRes.Msgs, bobRes.Msgs, charlieRes.Msgs, 'charlie')
    })
}

const makeSignOptions = (participants, config, bytes, sessionId) => {
    return JSON.stringify({
        Signers: participants,
        Config: config,
        HashToSign: bytes,
        SessionId: sessionId
    })
}

//sign()
async function sign() {
    bytes = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,]
    aliceOpts = makeSignOptions(['alice', 'bob'], aliceConfig, bytes, "dummySession")
    bobOpts = makeSignOptions(['alice', 'bob'], bobConfig, bytes, "dummySession")

    await aliceSignStart()
    await bobSignStart()
    await updateSParams()
    await aliceSignAdvance()
    await bobSignAdvance()
    await updateSParams()
    await aliceSignAdvance()
    await bobSignAdvance()
    await updateSParams()
    await aliceSignAdvance()
    await bobSignAdvance()
    await updateSParams()
    await aliceSignAdvance(true)
    await bobSignAdvance(true)
}

async function aliceSignStart() {
    aliceRes = JSON.parse(StartSignC(aliceOpts))
}

async function bobSignStart() {
    bobRes = JSON.parse(StartSignC(bobOpts))
}

async function aliceSignAdvance(printResult = false) {
    aliceRes = JSON.parse(ContSignC(aliceContParams))
    if (aliceRes.Sig !== null && aliceRes.SigEthereum !== null) {
        console.log("Sig: ", JSON.stringify(aliceRes.Sig))
        console.log("SigEthereum: ", JSON.stringify(aliceRes.SigEthereum))
        return
    }
    if (printResult) {
        console.log(JSON.stringify(aliceRes))
    }
}

async function bobSignAdvance(printResult = false) {
    bobRes = JSON.parse(ContSignC(bobContParams))
    if (bobRes.Sig !== null && bobRes.SigEthereum !== null) {
        console.log("Sig: ", JSON.stringify(bobRes.Sig))
        console.log("SigEthereum: ", JSON.stringify(bobRes.SigEthereum))
        return
    }
    if (printResult) {
        console.log(JSON.stringify(bobRes))
    }
}

async function updateSParams() {
    aliceContParams = JSON.stringify({
        Handler: aliceRes.Handler,
        Msgs: joinMessages(aliceRes.Msgs, bobRes.Msgs, [], 'alice')
    })
    bobContParams = JSON.stringify({
        Handler: bobRes.Handler,
        Msgs: joinMessages(aliceRes.Msgs, bobRes.Msgs, [], 'bob')
    })
}