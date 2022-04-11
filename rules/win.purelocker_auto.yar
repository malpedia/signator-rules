rule win_purelocker_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.purelocker."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.purelocker"
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
        $sequence_0 = { 89442420 eb3a ff74243c e8???????? 89442440 8b5c2440 }
            // n = 6, score = 100
            //   89442420             | mov                 dword ptr [esp + 0x20], eax
            //   eb3a                 | jmp                 0x3c
            //   ff74243c             | push                dword ptr [esp + 0x3c]
            //   e8????????           |                     
            //   89442440             | mov                 dword ptr [esp + 0x40], eax
            //   8b5c2440             | mov                 ebx, dword ptr [esp + 0x40]

        $sequence_1 = { 6801000000 e8???????? 89442408 8b5c2408 21db 751e c68424a000000001 }
            // n = 7, score = 100
            //   6801000000           | push                1
            //   e8????????           |                     
            //   89442408             | mov                 dword ptr [esp + 8], eax
            //   8b5c2408             | mov                 ebx, dword ptr [esp + 8]
            //   21db                 | and                 ebx, ebx
            //   751e                 | jne                 0x20
            //   c68424a000000001     | mov                 byte ptr [esp + 0xa0], 1

        $sequence_2 = { 0fb6410f c1e208 33d0 8bc3 33550c c1e808 8bca }
            // n = 7, score = 100
            //   0fb6410f             | movzx               eax, byte ptr [ecx + 0xf]
            //   c1e208               | shl                 edx, 8
            //   33d0                 | xor                 edx, eax
            //   8bc3                 | mov                 eax, ebx
            //   33550c               | xor                 edx, dword ptr [ebp + 0xc]
            //   c1e808               | shr                 eax, 8
            //   8bca                 | mov                 ecx, edx

        $sequence_3 = { 25ff000000 894c2424 8b0c9d20280110 330c85202c0110 8bc6 330c9520240110 }
            // n = 6, score = 100
            //   25ff000000           | and                 eax, 0xff
            //   894c2424             | mov                 dword ptr [esp + 0x24], ecx
            //   8b0c9d20280110       | mov                 ecx, dword ptr [ebx*4 + 0x10012820]
            //   330c85202c0110       | xor                 ecx, dword ptr [eax*4 + 0x10012c20]
            //   8bc6                 | mov                 eax, esi
            //   330c9520240110       | xor                 ecx, dword ptr [edx*4 + 0x10012420]

        $sequence_4 = { 8d05ac400110 50 e8???????? e8???????? }
            // n = 4, score = 100
            //   8d05ac400110         | lea                 eax, dword ptr [0x100140ac]
            //   50                   | push                eax
            //   e8????????           |                     
            //   e8????????           |                     

        $sequence_5 = { ff35???????? 58 890424 ff742430 ff742430 0fbe442430 50 }
            // n = 7, score = 100
            //   ff35????????         |                     
            //   58                   | pop                 eax
            //   890424               | mov                 dword ptr [esp], eax
            //   ff742430             | push                dword ptr [esp + 0x30]
            //   ff742430             | push                dword ptr [esp + 0x30]
            //   0fbe442430           | movsx               eax, byte ptr [esp + 0x30]
            //   50                   | push                eax

        $sequence_6 = { 8b5c2404 035c242c 035c2434 53 ffb4245c080000 }
            // n = 5, score = 100
            //   8b5c2404             | mov                 ebx, dword ptr [esp + 4]
            //   035c242c             | add                 ebx, dword ptr [esp + 0x2c]
            //   035c2434             | add                 ebx, dword ptr [esp + 0x34]
            //   53                   | push                ebx
            //   ffb4245c080000       | push                dword ptr [esp + 0x85c]

        $sequence_7 = { 8b4c2408 5d 895004 89480c 8b442448 5b }
            // n = 6, score = 100
            //   8b4c2408             | mov                 ecx, dword ptr [esp + 8]
            //   5d                   | pop                 ebp
            //   895004               | mov                 dword ptr [eax + 4], edx
            //   89480c               | mov                 dword ptr [eax + 0xc], ecx
            //   8b442448             | mov                 eax, dword ptr [esp + 0x48]
            //   5b                   | pop                 ebx

        $sequence_8 = { 8d05c0550110 50 e8???????? e8???????? 89c2 8b0c24 }
            // n = 6, score = 100
            //   8d05c0550110         | lea                 eax, dword ptr [0x100155c0]
            //   50                   | push                eax
            //   e8????????           |                     
            //   e8????????           |                     
            //   89c2                 | mov                 edx, eax
            //   8b0c24               | mov                 ecx, dword ptr [esp]

        $sequence_9 = { 8d442424 50 58 894508 8d442404 50 e8???????? }
            // n = 7, score = 100
            //   8d442424             | lea                 eax, dword ptr [esp + 0x24]
            //   50                   | push                eax
            //   58                   | pop                 eax
            //   894508               | mov                 dword ptr [ebp + 8], eax
            //   8d442404             | lea                 eax, dword ptr [esp + 4]
            //   50                   | push                eax
            //   e8????????           |                     

    condition:
        7 of them and filesize < 193536
}