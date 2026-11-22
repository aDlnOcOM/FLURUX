"""SHA-256 of Windows release files, derived from verified release archives."""

GUARD_HASH = "99e21ddc7b24f6422917e6b1eee6dfc0bee2ce7c98f6f888d8fe4dd51cc4565d"
ENGINE_FILES = {
    "8f30682ee198855440d2a7fe070d5d3653793b2d01bb8c85eea88f93bbe7c8b9": {
        "libcronet.dll": "3217c6260fbca5f16072e0b79735742f40109a63bb0ff88fd6b96dd6b54a2928",
        "sing-box.exe": "8f30682ee198855440d2a7fe070d5d3653793b2d01bb8c85eea88f93bbe7c8b9",
    },
    "0cebf40f8cea3ca4ad3673c8bdd8c9865242415be7afa190981ae655100b1b86": {
        "libcronet.dll": "8b005a933ac0d0899c047617a9cd18418810d9426d0919c824520094a2c893f5",
        "sing-box.exe": "0cebf40f8cea3ca4ad3673c8bdd8c9865242415be7afa190981ae655100b1b86",
    },
    "1ca7a2cf61ba2c5d20b21a80d405b57933939751081cb289f07bd8ddf7cc3185": {
        "wintun.dll": "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce",
        "xray.exe": "1ca7a2cf61ba2c5d20b21a80d405b57933939751081cb289f07bd8ddf7cc3185",
    },
}

TOR_FILES = {
    "lyrebird.exe": "9339fb4b7a41fab806e6a7961dc15afed29b8931291c4d2b756db74c471438ac",
    "tor.exe": "da22856f95ee24f8ace4ad1ab04acbd818fd6c3042bc3cf8f1d7cc3fa3edcb2b",
}
