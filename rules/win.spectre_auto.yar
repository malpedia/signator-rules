rule win_spectre_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-01-25"
        version = "1"
        description = "Detects win.spectre."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.spectre"
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
        $sequence_0 = { 3bc8 740f c644241000 ff742410 50 e8???????? 8d4c2454 }
            // n = 7, score = 100
            //   3bc8                 | cmp                 ecx, eax
            //   740f                 | je                  0x11
            //   c644241000           | mov                 byte ptr [esp + 0x10], 0
            //   ff742410             | push                dword ptr [esp + 0x10]
            //   50                   | push                eax
            //   e8????????           |                     
            //   8d4c2454             | lea                 ecx, [esp + 0x54]

        $sequence_1 = { 8d442460 8d742460 0f43442460 0f43742460 50 e8???????? 50 }
            // n = 7, score = 100
            //   8d442460             | lea                 eax, [esp + 0x60]
            //   8d742460             | lea                 esi, [esp + 0x60]
            //   0f43442460           | cmovae              eax, dword ptr [esp + 0x60]
            //   0f43742460           | cmovae              esi, dword ptr [esp + 0x60]
            //   50                   | push                eax
            //   e8????????           |                     
            //   50                   | push                eax

        $sequence_2 = { 7236 8b4c241c 40 89442418 894c2410 3d00100000 7219 }
            // n = 7, score = 100
            //   7236                 | jb                  0x38
            //   8b4c241c             | mov                 ecx, dword ptr [esp + 0x1c]
            //   40                   | inc                 eax
            //   89442418             | mov                 dword ptr [esp + 0x18], eax
            //   894c2410             | mov                 dword ptr [esp + 0x10], ecx
            //   3d00100000           | cmp                 eax, 0x1000
            //   7219                 | jb                  0x1b

        $sequence_3 = { c744240c33263322 c644241047 3b8104000000 7f15 eb01 5b }
            // n = 6, score = 100
            //   c744240c33263322     | mov                 dword ptr [esp + 0xc], 0x22332633
            //   c644241047           | mov                 byte ptr [esp + 0x10], 0x47
            //   3b8104000000         | cmp                 eax, dword ptr [ecx + 4]
            //   7f15                 | jg                  0x17
            //   eb01                 | jmp                 3
            //   5b                   | pop                 ebx

        $sequence_4 = { 59 5f 5e ebb4 83ec14 a1???????? 33c4 }
            // n = 7, score = 100
            //   59                   | pop                 ecx
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   ebb4                 | jmp                 0xffffffb6
            //   83ec14               | sub                 esp, 0x14
            //   a1????????           |                     
            //   33c4                 | xor                 eax, esp

        $sequence_5 = { c74430e084d74500 8b46e0 8b5004 8d42e0 894432dc 8b46f0 8b4004 }
            // n = 7, score = 100
            //   c74430e084d74500     | mov                 dword ptr [eax + esi - 0x20], 0x45d784
            //   8b46e0               | mov                 eax, dword ptr [esi - 0x20]
            //   8b5004               | mov                 edx, dword ptr [eax + 4]
            //   8d42e0               | lea                 eax, [edx - 0x20]
            //   894432dc             | mov                 dword ptr [edx + esi - 0x24], eax
            //   8b46f0               | mov                 eax, dword ptr [esi - 0x10]
            //   8b4004               | mov                 eax, dword ptr [eax + 4]

        $sequence_6 = { bd???????? c744240818343326 8b0c88 a1???????? c744240c33227a47 3b8104000000 7f15 }
            // n = 7, score = 100
            //   bd????????           |                     
            //   c744240818343326     | mov                 dword ptr [esp + 8], 0x26333418
            //   8b0c88               | mov                 ecx, dword ptr [eax + ecx*4]
            //   a1????????           |                     
            //   c744240c33227a47     | mov                 dword ptr [esp + 0xc], 0x477a2233
            //   3b8104000000         | cmp                 eax, dword ptr [ecx + 4]
            //   7f15                 | jg                  0x17

        $sequence_7 = { e8???????? 8b0f 3b4f08 7533 53 8bce e8???????? }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8b0f                 | mov                 ecx, dword ptr [edi]
            //   3b4f08               | cmp                 ecx, dword ptr [edi + 8]
            //   7533                 | jne                 0x35
            //   53                   | push                ebx
            //   8bce                 | mov                 ecx, esi
            //   e8????????           |                     

        $sequence_8 = { 3bc8 740f c644245000 ff742450 50 e8???????? 8d8c24ec000000 }
            // n = 7, score = 100
            //   3bc8                 | cmp                 ecx, eax
            //   740f                 | je                  0x11
            //   c644245000           | mov                 byte ptr [esp + 0x50], 0
            //   ff742450             | push                dword ptr [esp + 0x50]
            //   50                   | push                eax
            //   e8????????           |                     
            //   8d8c24ec000000       | lea                 ecx, [esp + 0xec]

        $sequence_9 = { e8???????? 83c40c 50 8d442460 50 e8???????? 83c40c }
            // n = 7, score = 100
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   50                   | push                eax
            //   8d442460             | lea                 eax, [esp + 0x60]
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc

    condition:
        7 of them and filesize < 990208
}