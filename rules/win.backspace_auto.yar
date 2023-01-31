rule win_backspace_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-01-25"
        version = "1"
        description = "Detects win.backspace."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.backspace"
        malpedia_rule_date = "20230124"
        malpedia_hash = "2ee0eebba83dce3d019a90519f2f972c0fcf9686"
        malpedia_version = "20230125"
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
        $sequence_0 = { 51 ff30 e8???????? 59 59 c3 55 }
            // n = 7, score = 100
            //   51                   | push                ecx
            //   ff30                 | push                dword ptr [eax]
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   c3                   | ret                 
            //   55                   | push                ebp

        $sequence_1 = { 6a0e 68???????? e8???????? 6a0e 68???????? e8???????? 6a09 }
            // n = 7, score = 100
            //   6a0e                 | push                0xe
            //   68????????           |                     
            //   e8????????           |                     
            //   6a0e                 | push                0xe
            //   68????????           |                     
            //   e8????????           |                     
            //   6a09                 | push                9

        $sequence_2 = { 33c0 c3 55 8bec 81ec24010000 53 56 }
            // n = 7, score = 100
            //   33c0                 | xor                 eax, eax
            //   c3                   | ret                 
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   81ec24010000         | sub                 esp, 0x124
            //   53                   | push                ebx
            //   56                   | push                esi

        $sequence_3 = { 0fb6450b 83c410 ff85f0feffff 8a8405f8feffff 88450f }
            // n = 5, score = 100
            //   0fb6450b             | movzx               eax, byte ptr [ebp + 0xb]
            //   83c410               | add                 esp, 0x10
            //   ff85f0feffff         | inc                 dword ptr [ebp - 0x110]
            //   8a8405f8feffff       | mov                 al, byte ptr [ebp + eax - 0x108]
            //   88450f               | mov                 byte ptr [ebp + 0xf], al

        $sequence_4 = { 8d843578fdffff 50 e8???????? 8d8578ffffff 50 e8???????? 015dfc }
            // n = 7, score = 100
            //   8d843578fdffff       | lea                 eax, [ebp + esi - 0x288]
            //   50                   | push                eax
            //   e8????????           |                     
            //   8d8578ffffff         | lea                 eax, [ebp - 0x88]
            //   50                   | push                eax
            //   e8????????           |                     
            //   015dfc               | add                 dword ptr [ebp - 4], ebx

        $sequence_5 = { c6852bffffff37 c6852cffffff38 c6852dffffff39 c6852effffff3a }
            // n = 4, score = 100
            //   c6852bffffff37       | mov                 byte ptr [ebp - 0xd5], 0x37
            //   c6852cffffff38       | mov                 byte ptr [ebp - 0xd4], 0x38
            //   c6852dffffff39       | mov                 byte ptr [ebp - 0xd3], 0x39
            //   c6852effffff3a       | mov                 byte ptr [ebp - 0xd2], 0x3a

        $sequence_6 = { 8be8 33db 3beb 0f84a8010000 }
            // n = 4, score = 100
            //   8be8                 | mov                 ebp, eax
            //   33db                 | xor                 ebx, ebx
            //   3beb                 | cmp                 ebp, ebx
            //   0f84a8010000         | je                  0x1ae

        $sequence_7 = { 85c0 741b 395df8 7cc8 ff75fc }
            // n = 5, score = 100
            //   85c0                 | test                eax, eax
            //   741b                 | je                  0x1d
            //   395df8               | cmp                 dword ptr [ebp - 8], ebx
            //   7cc8                 | jl                  0xffffffca
            //   ff75fc               | push                dword ptr [ebp - 4]

        $sequence_8 = { 8945e8 8d45e4 6a10 50 ff35???????? ff15???????? 8d45f4 }
            // n = 7, score = 100
            //   8945e8               | mov                 dword ptr [ebp - 0x18], eax
            //   8d45e4               | lea                 eax, [ebp - 0x1c]
            //   6a10                 | push                0x10
            //   50                   | push                eax
            //   ff35????????         |                     
            //   ff15????????         |                     
            //   8d45f4               | lea                 eax, [ebp - 0xc]

        $sequence_9 = { 59 8bc7 5f 5e c9 c3 833d????????00 }
            // n = 7, score = 100
            //   59                   | pop                 ecx
            //   8bc7                 | mov                 eax, edi
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   c9                   | leave               
            //   c3                   | ret                 
            //   833d????????00       |                     

    condition:
        7 of them and filesize < 131072
}