rule win_moonwind_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.moonwind."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.moonwind"
        malpedia_rule_date = "20230328"
        malpedia_hash = "9d2d75cef573c1c2d861f5197df8f563b05a305d"
        malpedia_version = "20230407"
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
        $sequence_0 = { 57 0f87de010000 743d 83e802 7422 83e80e 0f85d5010000 }
            // n = 7, score = 100
            //   57                   | push                edi
            //   0f87de010000         | ja                  0x1e4
            //   743d                 | je                  0x3f
            //   83e802               | sub                 eax, 2
            //   7422                 | je                  0x24
            //   83e80e               | sub                 eax, 0xe
            //   0f85d5010000         | jne                 0x1db

        $sequence_1 = { 51 52 e8???????? 83c40c b001 8b4df0 64890d00000000 }
            // n = 7, score = 100
            //   51                   | push                ecx
            //   52                   | push                edx
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   b001                 | mov                 al, 1
            //   8b4df0               | mov                 ecx, dword ptr [ebp - 0x10]
            //   64890d00000000       | mov                 dword ptr fs:[0], ecx

        $sequence_2 = { 58 8945ec e9???????? 6804000080 6a00 a1???????? 85c0 }
            // n = 7, score = 100
            //   58                   | pop                 eax
            //   8945ec               | mov                 dword ptr [ebp - 0x14], eax
            //   e9????????           |                     
            //   6804000080           | push                0x80000004
            //   6a00                 | push                0
            //   a1????????           |                     
            //   85c0                 | test                eax, eax

        $sequence_3 = { 83c410 33c9 3955e4 7f08 7c05 3945e0 7301 }
            // n = 7, score = 100
            //   83c410               | add                 esp, 0x10
            //   33c9                 | xor                 ecx, ecx
            //   3955e4               | cmp                 dword ptr [ebp - 0x1c], edx
            //   7f08                 | jg                  0xa
            //   7c05                 | jl                  7
            //   3945e0               | cmp                 dword ptr [ebp - 0x20], eax
            //   7301                 | jae                 3

        $sequence_4 = { 83ec20 8b450c 56 6a00 6a20 6a03 6a00 }
            // n = 7, score = 100
            //   83ec20               | sub                 esp, 0x20
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   56                   | push                esi
            //   6a00                 | push                0
            //   6a20                 | push                0x20
            //   6a03                 | push                3
            //   6a00                 | push                0

        $sequence_5 = { e8???????? c705????????02000000 c705????????01000000 c705????????00000000 e9???????? e9???????? c745fc00000000 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   c705????????02000000     |     
            //   c705????????01000000     |     
            //   c705????????00000000     |     
            //   e9????????           |                     
            //   e9????????           |                     
            //   c745fc00000000       | mov                 dword ptr [ebp - 4], 0

        $sequence_6 = { e8???????? 83c410 894594 8b5d98 85db 7409 53 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10
            //   894594               | mov                 dword ptr [ebp - 0x6c], eax
            //   8b5d98               | mov                 ebx, dword ptr [ebp - 0x68]
            //   85db                 | test                ebx, ebx
            //   7409                 | je                  0xb
            //   53                   | push                ebx

        $sequence_7 = { 8a45ca eb06 8b45c8 c1e818 3d9b000000 0f8775030000 33db }
            // n = 7, score = 100
            //   8a45ca               | mov                 al, byte ptr [ebp - 0x36]
            //   eb06                 | jmp                 8
            //   8b45c8               | mov                 eax, dword ptr [ebp - 0x38]
            //   c1e818               | shr                 eax, 0x18
            //   3d9b000000           | cmp                 eax, 0x9b
            //   0f8775030000         | ja                  0x37b
            //   33db                 | xor                 ebx, ebx

        $sequence_8 = { 8903 e9???????? 8b5d08 8b1b 83c314 895db4 8b5db4 }
            // n = 7, score = 100
            //   8903                 | mov                 dword ptr [ebx], eax
            //   e9????????           |                     
            //   8b5d08               | mov                 ebx, dword ptr [ebp + 8]
            //   8b1b                 | mov                 ebx, dword ptr [ebx]
            //   83c314               | add                 ebx, 0x14
            //   895db4               | mov                 dword ptr [ebp - 0x4c], ebx
            //   8b5db4               | mov                 ebx, dword ptr [ebp - 0x4c]

        $sequence_9 = { 8919 8b551c 891a 8b452c c70000000000 eb22 8b550c }
            // n = 7, score = 100
            //   8919                 | mov                 dword ptr [ecx], ebx
            //   8b551c               | mov                 edx, dword ptr [ebp + 0x1c]
            //   891a                 | mov                 dword ptr [edx], ebx
            //   8b452c               | mov                 eax, dword ptr [ebp + 0x2c]
            //   c70000000000         | mov                 dword ptr [eax], 0
            //   eb22                 | jmp                 0x24
            //   8b550c               | mov                 edx, dword ptr [ebp + 0xc]

    condition:
        7 of them and filesize < 1417216
}