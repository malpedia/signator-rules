rule win_tinytyphon_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.tinytyphon."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.tinytyphon"
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
        $sequence_0 = { 8b55e0 c1e20a 8b45e0 c1e816 0bd0 }
            // n = 5, score = 200
            //   8b55e0               | mov                 edx, dword ptr [ebp - 0x20]
            //   c1e20a               | shl                 edx, 0xa
            //   8b45e0               | mov                 eax, dword ptr [ebp - 0x20]
            //   c1e816               | shr                 eax, 0x16
            //   0bd0                 | or                  edx, eax

        $sequence_1 = { 0bd1 8b45f4 0fb6480f c1e118 0bd1 8b4508 895064 }
            // n = 7, score = 200
            //   0bd1                 | or                  edx, ecx
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]
            //   0fb6480f             | movzx               ecx, byte ptr [eax + 0xf]
            //   c1e118               | shl                 ecx, 0x18
            //   0bd1                 | or                  edx, ecx
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   895064               | mov                 dword ptr [eax + 0x64], edx

        $sequence_2 = { 50 8d8df0fdffff 51 ff15???????? 6a00 8d95f0fdffff 52 }
            // n = 7, score = 200
            //   50                   | push                eax
            //   8d8df0fdffff         | lea                 ecx, dword ptr [ebp - 0x210]
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   6a00                 | push                0
            //   8d95f0fdffff         | lea                 edx, dword ptr [ebp - 0x210]
            //   52                   | push                edx

        $sequence_3 = { ff15???????? 8b15???????? 8995f4feffff eb0e 8b85f4feffff 8b08 898df4feffff }
            // n = 7, score = 200
            //   ff15????????         |                     
            //   8b15????????         |                     
            //   8995f4feffff         | mov                 dword ptr [ebp - 0x10c], edx
            //   eb0e                 | jmp                 0x10
            //   8b85f4feffff         | mov                 eax, dword ptr [ebp - 0x10c]
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   898df4feffff         | mov                 dword ptr [ebp - 0x10c], ecx

        $sequence_4 = { 7e2d 8b45f0 8945f8 8b4dfc 8b55f0 8b02 }
            // n = 6, score = 200
            //   7e2d                 | jle                 0x2f
            //   8b45f0               | mov                 eax, dword ptr [ebp - 0x10]
            //   8945f8               | mov                 dword ptr [ebp - 8], eax
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   8b55f0               | mov                 edx, dword ptr [ebp - 0x10]
            //   8b02                 | mov                 eax, dword ptr [edx]

        $sequence_5 = { 234de4 334df8 8b5508 038a84000000 8b45dc }
            // n = 5, score = 200
            //   234de4               | and                 ecx, dword ptr [ebp - 0x1c]
            //   334df8               | xor                 ecx, dword ptr [ebp - 8]
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   038a84000000         | add                 ecx, dword ptr [edx + 0x84]
            //   8b45dc               | mov                 eax, dword ptr [ebp - 0x24]

        $sequence_6 = { 898558ffffff 83bd58ffffff00 7409 83bd58ffffffff 750a b801000000 e9???????? }
            // n = 7, score = 200
            //   898558ffffff         | mov                 dword ptr [ebp - 0xa8], eax
            //   83bd58ffffff00       | cmp                 dword ptr [ebp - 0xa8], 0
            //   7409                 | je                  0xb
            //   83bd58ffffffff       | cmp                 dword ptr [ebp - 0xa8], -1
            //   750a                 | jne                 0xc
            //   b801000000           | mov                 eax, 1
            //   e9????????           |                     

        $sequence_7 = { 0fb64827 c1e118 0bd1 8b4508 89507c }
            // n = 5, score = 200
            //   0fb64827             | movzx               ecx, byte ptr [eax + 0x27]
            //   c1e118               | shl                 ecx, 0x18
            //   0bd1                 | or                  edx, ecx
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   89507c               | mov                 dword ptr [eax + 0x7c], edx

        $sequence_8 = { ff15???????? 037514 03c6 8985d4feffff 8b95d4feffff }
            // n = 5, score = 200
            //   ff15????????         |                     
            //   037514               | add                 esi, dword ptr [ebp + 0x14]
            //   03c6                 | add                 eax, esi
            //   8985d4feffff         | mov                 dword ptr [ebp - 0x12c], eax
            //   8b95d4feffff         | mov                 edx, dword ptr [ebp - 0x12c]

        $sequence_9 = { 55 8bec 83ec10 c745fc???????? a1???????? }
            // n = 5, score = 200
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   83ec10               | sub                 esp, 0x10
            //   c745fc????????       |                     
            //   a1????????           |                     

    condition:
        7 of them and filesize < 90112
}