rule win_roseam_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.roseam."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.roseam"
        malpedia_rule_date = "20221118"
        malpedia_hash = "e0702e2e6d1d00da65c8a29a4ebacd0a4c59e1af"
        malpedia_version = "20221125"
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
        $sequence_0 = { 0f859e000000 68???????? 50 9c }
            // n = 4, score = 100
            //   0f859e000000         | jne                 0xa4
            //   68????????           |                     
            //   50                   | push                eax
            //   9c                   | pushfd              

        $sequence_1 = { c745ec0c000000 8938 897804 897808 89780c 50 50 }
            // n = 7, score = 100
            //   c745ec0c000000       | mov                 dword ptr [ebp - 0x14], 0xc
            //   8938                 | mov                 dword ptr [eax], edi
            //   897804               | mov                 dword ptr [eax + 4], edi
            //   897808               | mov                 dword ptr [eax + 8], edi
            //   89780c               | mov                 dword ptr [eax + 0xc], edi
            //   50                   | push                eax
            //   50                   | push                eax

        $sequence_2 = { 895508 89450c 0f85a9fcffff 68???????? }
            // n = 4, score = 100
            //   895508               | mov                 dword ptr [ebp + 8], edx
            //   89450c               | mov                 dword ptr [ebp + 0xc], eax
            //   0f85a9fcffff         | jne                 0xfffffcaf
            //   68????????           |                     

        $sequence_3 = { 81ecc4000000 56 57 b91f000000 33c0 8dbd3effffff 66c7853cffffff0000 }
            // n = 7, score = 100
            //   81ecc4000000         | sub                 esp, 0xc4
            //   56                   | push                esi
            //   57                   | push                edi
            //   b91f000000           | mov                 ecx, 0x1f
            //   33c0                 | xor                 eax, eax
            //   8dbd3effffff         | lea                 edi, [ebp - 0xc2]
            //   66c7853cffffff0000     | mov    word ptr [ebp - 0xc4], 0

        $sequence_4 = { 83c9ff 33c0 f2ae f7d1 2bf9 8d95f4fcffff }
            // n = 6, score = 100
            //   83c9ff               | or                  ecx, 0xffffffff
            //   33c0                 | xor                 eax, eax
            //   f2ae                 | repne scasb         al, byte ptr es:[edi]
            //   f7d1                 | not                 ecx
            //   2bf9                 | sub                 edi, ecx
            //   8d95f4fcffff         | lea                 edx, [ebp - 0x30c]

        $sequence_5 = { 6689b504eeffff f3ab 66ab b9ff000000 33c0 }
            // n = 5, score = 100
            //   6689b504eeffff       | mov                 word ptr [ebp - 0x11fc], si
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax
            //   66ab                 | stosw               word ptr es:[edi], ax
            //   b9ff000000           | mov                 ecx, 0xff
            //   33c0                 | xor                 eax, eax

        $sequence_6 = { 5f 5e 5b 8be5 5d c3 80bd58ffffff41 }
            // n = 7, score = 100
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx
            //   8be5                 | mov                 esp, ebp
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   80bd58ffffff41       | cmp                 byte ptr [ebp - 0xa8], 0x41

        $sequence_7 = { 33d2 b9ff000000 33c0 8dbdf1fbffff }
            // n = 4, score = 100
            //   33d2                 | xor                 edx, edx
            //   b9ff000000           | mov                 ecx, 0xff
            //   33c0                 | xor                 eax, eax
            //   8dbdf1fbffff         | lea                 edi, [ebp - 0x40f]

        $sequence_8 = { 81ec90040000 53 56 57 b97f000000 }
            // n = 5, score = 100
            //   81ec90040000         | sub                 esp, 0x490
            //   53                   | push                ebx
            //   56                   | push                esi
            //   57                   | push                edi
            //   b97f000000           | mov                 ecx, 0x7f

        $sequence_9 = { f7d1 49 8955f8 894df4 c6451041 50 }
            // n = 6, score = 100
            //   f7d1                 | not                 ecx
            //   49                   | dec                 ecx
            //   8955f8               | mov                 dword ptr [ebp - 8], edx
            //   894df4               | mov                 dword ptr [ebp - 0xc], ecx
            //   c6451041             | mov                 byte ptr [ebp + 0x10], 0x41
            //   50                   | push                eax

    condition:
        7 of them and filesize < 221184
}