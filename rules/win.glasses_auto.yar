rule win_glasses_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.glasses."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.glasses"
        malpedia_rule_date = "20220513"
        malpedia_hash = "7f4b2229e6ae614d86d74917f6d5b41890e62a26"
        malpedia_version = "20220516"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    /* DISCLAIMER
     * The strings used in this rule have been automatically selected from the
     * disassembly of memory dumps and unpacked files, using YARA-Signator.
     * The code and documentation is published here:
     * https://github.com/fxb-cocacoding/yara-signator
     * As Malpedia is used as data source, please note that for a given
     * number of families, only single samples are documented.
     * This likely impacts the degree of generalization these rules will offer.
     * Take the described generation method also into consideration when you
     * apply the rules in your use cases and assign them confidence levels.
     */


    strings:
        $sequence_0 = { c645fc02 e8???????? 8d8e48110000 c645fc01 e8???????? 8d8e980e0000 c645fc00 }
            // n = 7, score = 100
            //   c645fc02             | mov                 byte ptr [ebp - 4], 2
            //   e8????????           |                     
            //   8d8e48110000         | lea                 ecx, [esi + 0x1148]
            //   c645fc01             | mov                 byte ptr [ebp - 4], 1
            //   e8????????           |                     
            //   8d8e980e0000         | lea                 ecx, [esi + 0xe98]
            //   c645fc00             | mov                 byte ptr [ebp - 4], 0

        $sequence_1 = { e8???????? c7861829000000000000 8d8ebc270000 e8???????? 8d4de4 c645fc05 e8???????? }
            // n = 7, score = 100
            //   e8????????           |                     
            //   c7861829000000000000     | mov    dword ptr [esi + 0x2918], 0
            //   8d8ebc270000         | lea                 ecx, [esi + 0x27bc]
            //   e8????????           |                     
            //   8d4de4               | lea                 ecx, [ebp - 0x1c]
            //   c645fc05             | mov                 byte ptr [ebp - 4], 5
            //   e8????????           |                     

        $sequence_2 = { e8???????? 83c410 833d????????00 0f856bedffff 8935???????? b001 5e }
            // n = 7, score = 100
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10
            //   833d????????00       |                     
            //   0f856bedffff         | jne                 0xffffed71
            //   8935????????         |                     
            //   b001                 | mov                 al, 1
            //   5e                   | pop                 esi

        $sequence_3 = { e8???????? 50 8d8d40ffffff e8???????? 53 8d8d40ffffff e8???????? }
            // n = 7, score = 100
            //   e8????????           |                     
            //   50                   | push                eax
            //   8d8d40ffffff         | lea                 ecx, [ebp - 0xc0]
            //   e8????????           |                     
            //   53                   | push                ebx
            //   8d8d40ffffff         | lea                 ecx, [ebp - 0xc0]
            //   e8????????           |                     

        $sequence_4 = { c645fc01 e8???????? 85c0 7515 8b4308 85c0 740e }
            // n = 7, score = 100
            //   c645fc01             | mov                 byte ptr [ebp - 4], 1
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   7515                 | jne                 0x17
            //   8b4308               | mov                 eax, dword ptr [ebx + 8]
            //   85c0                 | test                eax, eax
            //   740e                 | je                  0x10

        $sequence_5 = { 8bd8 33ff 85db 7e15 8b4e30 8b492c 57 }
            // n = 7, score = 100
            //   8bd8                 | mov                 ebx, eax
            //   33ff                 | xor                 edi, edi
            //   85db                 | test                ebx, ebx
            //   7e15                 | jle                 0x17
            //   8b4e30               | mov                 ecx, dword ptr [esi + 0x30]
            //   8b492c               | mov                 ecx, dword ptr [ecx + 0x2c]
            //   57                   | push                edi

        $sequence_6 = { e8???????? 50 8d8d5cffffff e8???????? 50 e8???????? 83c410 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   50                   | push                eax
            //   8d8d5cffffff         | lea                 ecx, [ebp - 0xa4]
            //   e8????????           |                     
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10

        $sequence_7 = { e8???????? 8b5d0c 68???????? 68???????? 8d4e30 899ea4000000 e8???????? }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8b5d0c               | mov                 ebx, dword ptr [ebp + 0xc]
            //   68????????           |                     
            //   68????????           |                     
            //   8d4e30               | lea                 ecx, [esi + 0x30]
            //   899ea4000000         | mov                 dword ptr [esi + 0xa4], ebx
            //   e8????????           |                     

        $sequence_8 = { c687c40a000000 8b4e44 51 8d8dacfdffff e8???????? 8d8dc0fdffff c745fc00000000 }
            // n = 7, score = 100
            //   c687c40a000000       | mov                 byte ptr [edi + 0xac4], 0
            //   8b4e44               | mov                 ecx, dword ptr [esi + 0x44]
            //   51                   | push                ecx
            //   8d8dacfdffff         | lea                 ecx, [ebp - 0x254]
            //   e8????????           |                     
            //   8d8dc0fdffff         | lea                 ecx, [ebp - 0x240]
            //   c745fc00000000       | mov                 dword ptr [ebp - 4], 0

        $sequence_9 = { e9???????? 8d8d4cfbffff e9???????? 8d8df0f1f0ff e9???????? 8d8d44f1f0ff e9???????? }
            // n = 7, score = 100
            //   e9????????           |                     
            //   8d8d4cfbffff         | lea                 ecx, [ebp - 0x4b4]
            //   e9????????           |                     
            //   8d8df0f1f0ff         | lea                 ecx, [ebp - 0xf0e10]
            //   e9????????           |                     
            //   8d8d44f1f0ff         | lea                 ecx, [ebp - 0xf0ebc]
            //   e9????????           |                     

    condition:
        7 of them and filesize < 4177920
}