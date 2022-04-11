rule win_multigrain_pos_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.multigrain_pos."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.multigrain_pos"
        malpedia_rule_date = "20220405"
        malpedia_hash = "ecd38294bd47d5589be5cd5490dc8bb4804afc2a"
        malpedia_version = ""
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
        $sequence_0 = { 83ec18 8bcc c645fc01 8965b8 33c0 6aff }
            // n = 6, score = 200
            //   83ec18               | sub                 esp, 0x18
            //   8bcc                 | mov                 ecx, esp
            //   c645fc01             | mov                 byte ptr [ebp - 4], 1
            //   8965b8               | mov                 dword ptr [ebp - 0x48], esp
            //   33c0                 | xor                 eax, eax
            //   6aff                 | push                -1

        $sequence_1 = { 83c404 33c0 837dd408 c745ec07000000 c745e800000000 668945d8 720b }
            // n = 7, score = 200
            //   83c404               | add                 esp, 4
            //   33c0                 | xor                 eax, eax
            //   837dd408             | cmp                 dword ptr [ebp - 0x2c], 8
            //   c745ec07000000       | mov                 dword ptr [ebp - 0x14], 7
            //   c745e800000000       | mov                 dword ptr [ebp - 0x18], 0
            //   668945d8             | mov                 word ptr [ebp - 0x28], ax
            //   720b                 | jb                  0xd

        $sequence_2 = { c645fc01 e8???????? 83c408 83bdb4fdffff08 720e ffb5a0fdffff }
            // n = 6, score = 200
            //   c645fc01             | mov                 byte ptr [ebp - 4], 1
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   83bdb4fdffff08       | cmp                 dword ptr [ebp - 0x24c], 8
            //   720e                 | jb                  0x10
            //   ffb5a0fdffff         | push                dword ptr [ebp - 0x260]

        $sequence_3 = { 50 8d145a e8???????? eb1f 837f1408 }
            // n = 5, score = 200
            //   50                   | push                eax
            //   8d145a               | lea                 edx, dword ptr [edx + ebx*2]
            //   e8????????           |                     
            //   eb1f                 | jmp                 0x21
            //   837f1408             | cmp                 dword ptr [edi + 0x14], 8

        $sequence_4 = { 6a00 c746140f000000 c7461000000000 c60600 68???????? eb3e ff15???????? }
            // n = 7, score = 200
            //   6a00                 | push                0
            //   c746140f000000       | mov                 dword ptr [esi + 0x14], 0xf
            //   c7461000000000       | mov                 dword ptr [esi + 0x10], 0
            //   c60600               | mov                 byte ptr [esi], 0
            //   68????????           |                     
            //   eb3e                 | jmp                 0x40
            //   ff15????????         |                     

        $sequence_5 = { 3b01 0f823efeffff 8b55f8 5f }
            // n = 4, score = 200
            //   3b01                 | cmp                 eax, dword ptr [ecx]
            //   0f823efeffff         | jb                  0xfffffe44
            //   8b55f8               | mov                 edx, dword ptr [ebp - 8]
            //   5f                   | pop                 edi

        $sequence_6 = { 84d2 742c 3b33 751d ff7514 8d45e4 }
            // n = 6, score = 200
            //   84d2                 | test                dl, dl
            //   742c                 | je                  0x2e
            //   3b33                 | cmp                 esi, dword ptr [ebx]
            //   751d                 | jne                 0x1f
            //   ff7514               | push                dword ptr [ebp + 0x14]
            //   8d45e4               | lea                 eax, dword ptr [ebp - 0x1c]

        $sequence_7 = { c68524ffffff00 c645fc1a 83bd68ffffff10 720e ffb554ffffff e8???????? }
            // n = 6, score = 200
            //   c68524ffffff00       | mov                 byte ptr [ebp - 0xdc], 0
            //   c645fc1a             | mov                 byte ptr [ebp - 4], 0x1a
            //   83bd68ffffff10       | cmp                 dword ptr [ebp - 0x98], 0x10
            //   720e                 | jb                  0x10
            //   ffb554ffffff         | push                dword ptr [ebp - 0xac]
            //   e8????????           |                     

        $sequence_8 = { e9???????? 8d558c 8d4a01 8a02 42 84c0 75f9 }
            // n = 7, score = 200
            //   e9????????           |                     
            //   8d558c               | lea                 edx, dword ptr [ebp - 0x74]
            //   8d4a01               | lea                 ecx, dword ptr [edx + 1]
            //   8a02                 | mov                 al, byte ptr [edx]
            //   42                   | inc                 edx
            //   84c0                 | test                al, al
            //   75f9                 | jne                 0xfffffffb

        $sequence_9 = { ff30 8d45fc 50 8d8f04040000 e8???????? ffb704040000 e8???????? }
            // n = 7, score = 200
            //   ff30                 | push                dword ptr [eax]
            //   8d45fc               | lea                 eax, dword ptr [ebp - 4]
            //   50                   | push                eax
            //   8d8f04040000         | lea                 ecx, dword ptr [edi + 0x404]
            //   e8????????           |                     
            //   ffb704040000         | push                dword ptr [edi + 0x404]
            //   e8????????           |                     

    condition:
        7 of them and filesize < 286720
}