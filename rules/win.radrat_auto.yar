rule win_radrat_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.radrat."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.radrat"
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
        $sequence_0 = { c745fc40000000 8b95ec7dffff 8995f47dffff 8b85f47dffff 89854c9fffff 8b8d4c9fffff 51 }
            // n = 7, score = 100
            //   c745fc40000000       | mov                 dword ptr [ebp - 4], 0x40
            //   8b95ec7dffff         | mov                 edx, dword ptr [ebp - 0x8214]
            //   8995f47dffff         | mov                 dword ptr [ebp - 0x820c], edx
            //   8b85f47dffff         | mov                 eax, dword ptr [ebp - 0x820c]
            //   89854c9fffff         | mov                 dword ptr [ebp - 0x60b4], eax
            //   8b8d4c9fffff         | mov                 ecx, dword ptr [ebp - 0x60b4]
            //   51                   | push                ecx

        $sequence_1 = { c3 8d4d80 e8???????? c3 8d4dac e8???????? c3 }
            // n = 7, score = 100
            //   c3                   | ret                 
            //   8d4d80               | lea                 ecx, dword ptr [ebp - 0x80]
            //   e8????????           |                     
            //   c3                   | ret                 
            //   8d4dac               | lea                 ecx, dword ptr [ebp - 0x54]
            //   e8????????           |                     
            //   c3                   | ret                 

        $sequence_2 = { c645fc03 8d8d20ffffff e8???????? c645fc02 8d8d48ffffff e8???????? c685f4feffff00 }
            // n = 7, score = 100
            //   c645fc03             | mov                 byte ptr [ebp - 4], 3
            //   8d8d20ffffff         | lea                 ecx, dword ptr [ebp - 0xe0]
            //   e8????????           |                     
            //   c645fc02             | mov                 byte ptr [ebp - 4], 2
            //   8d8d48ffffff         | lea                 ecx, dword ptr [ebp - 0xb8]
            //   e8????????           |                     
            //   c685f4feffff00       | mov                 byte ptr [ebp - 0x10c], 0

        $sequence_3 = { 8d8db8c4ffff e8???????? c645fc3a 8d8decc4ffff e8???????? c745fc02000000 8d8de4c4ffff }
            // n = 7, score = 100
            //   8d8db8c4ffff         | lea                 ecx, dword ptr [ebp - 0x3b48]
            //   e8????????           |                     
            //   c645fc3a             | mov                 byte ptr [ebp - 4], 0x3a
            //   8d8decc4ffff         | lea                 ecx, dword ptr [ebp - 0x3b14]
            //   e8????????           |                     
            //   c745fc02000000       | mov                 dword ptr [ebp - 4], 2
            //   8d8de4c4ffff         | lea                 ecx, dword ptr [ebp - 0x3b1c]

        $sequence_4 = { e8???????? 83c40c c645fc1c 8d8dacfaffff e8???????? c645fc1b 8d8dd4faffff }
            // n = 7, score = 100
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   c645fc1c             | mov                 byte ptr [ebp - 4], 0x1c
            //   8d8dacfaffff         | lea                 ecx, dword ptr [ebp - 0x554]
            //   e8????????           |                     
            //   c645fc1b             | mov                 byte ptr [ebp - 4], 0x1b
            //   8d8dd4faffff         | lea                 ecx, dword ptr [ebp - 0x52c]

        $sequence_5 = { 8d95ccfeffff 52 8d4dcc e8???????? 8985d8fdffff 8b85d8fdffff 8985d4fdffff }
            // n = 7, score = 100
            //   8d95ccfeffff         | lea                 edx, dword ptr [ebp - 0x134]
            //   52                   | push                edx
            //   8d4dcc               | lea                 ecx, dword ptr [ebp - 0x34]
            //   e8????????           |                     
            //   8985d8fdffff         | mov                 dword ptr [ebp - 0x228], eax
            //   8b85d8fdffff         | mov                 eax, dword ptr [ebp - 0x228]
            //   8985d4fdffff         | mov                 dword ptr [ebp - 0x22c], eax

        $sequence_6 = { 8bec 83ec10 56 57 894df0 8b45f0 83781000 }
            // n = 7, score = 100
            //   8bec                 | mov                 ebp, esp
            //   83ec10               | sub                 esp, 0x10
            //   56                   | push                esi
            //   57                   | push                edi
            //   894df0               | mov                 dword ptr [ebp - 0x10], ecx
            //   8b45f0               | mov                 eax, dword ptr [ebp - 0x10]
            //   83781000             | cmp                 dword ptr [eax + 0x10], 0

        $sequence_7 = { e8???????? c745fcffffffff 8d4d80 e8???????? 8a85a898ffff e9???????? 6a00 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   c745fcffffffff       | mov                 dword ptr [ebp - 4], 0xffffffff
            //   8d4d80               | lea                 ecx, dword ptr [ebp - 0x80]
            //   e8????????           |                     
            //   8a85a898ffff         | mov                 al, byte ptr [ebp - 0x6758]
            //   e9????????           |                     
            //   6a00                 | push                0

        $sequence_8 = { e8???????? c3 8d8d74feffff e8???????? c3 8d8d4cfeffff e8???????? }
            // n = 7, score = 100
            //   e8????????           |                     
            //   c3                   | ret                 
            //   8d8d74feffff         | lea                 ecx, dword ptr [ebp - 0x18c]
            //   e8????????           |                     
            //   c3                   | ret                 
            //   8d8d4cfeffff         | lea                 ecx, dword ptr [ebp - 0x1b4]
            //   e8????????           |                     

        $sequence_9 = { c3 8d8d78b8ffff e8???????? c3 8d8d3cb8ffff e8???????? c3 }
            // n = 7, score = 100
            //   c3                   | ret                 
            //   8d8d78b8ffff         | lea                 ecx, dword ptr [ebp - 0x4788]
            //   e8????????           |                     
            //   c3                   | ret                 
            //   8d8d3cb8ffff         | lea                 ecx, dword ptr [ebp - 0x47c4]
            //   e8????????           |                     
            //   c3                   | ret                 

    condition:
        7 of them and filesize < 2080768
}