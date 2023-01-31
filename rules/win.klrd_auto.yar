rule win_klrd_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-01-25"
        version = "1"
        description = "Detects win.klrd."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.klrd"
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
        $sequence_0 = { ff75f0 ff75ec ff15???????? 8985d4feffff 83bdd4feffff00 7502 }
            // n = 6, score = 100
            //   ff75f0               | push                dword ptr [ebp - 0x10]
            //   ff75ec               | push                dword ptr [ebp - 0x14]
            //   ff15????????         |                     
            //   8985d4feffff         | mov                 dword ptr [ebp - 0x12c], eax
            //   83bdd4feffff00       | cmp                 dword ptr [ebp - 0x12c], 0
            //   7502                 | jne                 4

        $sequence_1 = { 50 ff15???????? c9 c3 8b45fc }
            // n = 5, score = 100
            //   50                   | push                eax
            //   ff15????????         |                     
            //   c9                   | leave               
            //   c3                   | ret                 
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]

        $sequence_2 = { 740d 817d0c00010000 0f85a6020000 8b7510 6a05 59 8d7dec }
            // n = 7, score = 100
            //   740d                 | je                  0xf
            //   817d0c00010000       | cmp                 dword ptr [ebp + 0xc], 0x100
            //   0f85a6020000         | jne                 0x2ac
            //   8b7510               | mov                 esi, dword ptr [ebp + 0x10]
            //   6a05                 | push                5
            //   59                   | pop                 ecx
            //   8d7dec               | lea                 edi, [ebp - 0x14]

        $sequence_3 = { e8???????? ff35???????? ff15???????? 53 ebd2 }
            // n = 5, score = 100
            //   e8????????           |                     
            //   ff35????????         |                     
            //   ff15????????         |                     
            //   53                   | push                ebx
            //   ebd2                 | jmp                 0xffffffd4

        $sequence_4 = { 59 ff7510 ff750c ff7508 ff35???????? ff15???????? 5f }
            // n = 7, score = 100
            //   59                   | pop                 ecx
            //   ff7510               | push                dword ptr [ebp + 0x10]
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   ff7508               | push                dword ptr [ebp + 8]
            //   ff35????????         |                     
            //   ff15????????         |                     
            //   5f                   | pop                 edi

        $sequence_5 = { 80bdacfcffff1b 741b 80bdacfcffff20 7432 eb57 68???????? e8???????? }
            // n = 7, score = 100
            //   80bdacfcffff1b       | cmp                 byte ptr [ebp - 0x354], 0x1b
            //   741b                 | je                  0x1d
            //   80bdacfcffff20       | cmp                 byte ptr [ebp - 0x354], 0x20
            //   7432                 | je                  0x34
            //   eb57                 | jmp                 0x59
            //   68????????           |                     
            //   e8????????           |                     

        $sequence_6 = { b804100000 e8???????? 56 57 8d450c }
            // n = 5, score = 100
            //   b804100000           | mov                 eax, 0x1004
            //   e8????????           |                     
            //   56                   | push                esi
            //   57                   | push                edi
            //   8d450c               | lea                 eax, [ebp + 0xc]

        $sequence_7 = { 53 50 889dfcfeffff e8???????? 83c40c 53 ff15???????? }
            // n = 7, score = 100
            //   53                   | push                ebx
            //   50                   | push                eax
            //   889dfcfeffff         | mov                 byte ptr [ebp - 0x104], bl
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   53                   | push                ebx
            //   ff15????????         |                     

        $sequence_8 = { 8d85fcfeffff 50 53 ff15???????? 8b35???????? }
            // n = 5, score = 100
            //   8d85fcfeffff         | lea                 eax, [ebp - 0x104]
            //   50                   | push                eax
            //   53                   | push                ebx
            //   ff15????????         |                     
            //   8b35????????         |                     

        $sequence_9 = { 8d45fc 50 8d85fcefffff 50 e8???????? }
            // n = 5, score = 100
            //   8d45fc               | lea                 eax, [ebp - 4]
            //   50                   | push                eax
            //   8d85fcefffff         | lea                 eax, [ebp - 0x1004]
            //   50                   | push                eax
            //   e8????????           |                     

    condition:
        7 of them and filesize < 40960
}