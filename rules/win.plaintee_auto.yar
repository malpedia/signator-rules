rule win_plaintee_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.plaintee."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.plaintee"
        malpedia_rule_date = "20231130"
        malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
        malpedia_version = "20230808"
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
        $sequence_0 = { 8d4c2404 6a00 8d542404 51 52 ffd0 8b4c2400 }
            // n = 7, score = 300
            //   8d4c2404             | lea                 ecx, [esp + 4]
            //   6a00                 | push                0
            //   8d542404             | lea                 edx, [esp + 4]
            //   51                   | push                ecx
            //   52                   | push                edx
            //   ffd0                 | call                eax
            //   8b4c2400             | mov                 ecx, dword ptr [esp]

        $sequence_1 = { 8bf1 6802020000 ff15???????? 85c0 740a b001 }
            // n = 6, score = 300
            //   8bf1                 | mov                 esi, ecx
            //   6802020000           | push                0x202
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   740a                 | je                  0xc
            //   b001                 | mov                 al, 1

        $sequence_2 = { 50 8d853c010000 50 8b8538010000 6a5a 52 }
            // n = 6, score = 300
            //   50                   | push                eax
            //   8d853c010000         | lea                 eax, [ebp + 0x13c]
            //   50                   | push                eax
            //   8b8538010000         | mov                 eax, dword ptr [ebp + 0x138]
            //   6a5a                 | push                0x5a
            //   52                   | push                edx

        $sequence_3 = { 8d442400 56 50 8bf1 6802020000 ff15???????? }
            // n = 6, score = 300
            //   8d442400             | lea                 eax, [esp]
            //   56                   | push                esi
            //   50                   | push                eax
            //   8bf1                 | mov                 esi, ecx
            //   6802020000           | push                0x202
            //   ff15????????         |                     

        $sequence_4 = { 5e 81c490010000 c3 8bce }
            // n = 4, score = 300
            //   5e                   | pop                 esi
            //   81c490010000         | add                 esp, 0x190
            //   c3                   | ret                 
            //   8bce                 | mov                 ecx, esi

        $sequence_5 = { 85f6 74c6 8bce e8???????? }
            // n = 4, score = 300
            //   85f6                 | test                esi, esi
            //   74c6                 | je                  0xffffffc8
            //   8bce                 | mov                 ecx, esi
            //   e8????????           |                     

        $sequence_6 = { f3ab 66ab b900010000 33c0 }
            // n = 4, score = 300
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax
            //   66ab                 | stosw               word ptr es:[edi], ax
            //   b900010000           | mov                 ecx, 0x100
            //   33c0                 | xor                 eax, eax

        $sequence_7 = { eb02 33f6 8bce e8???????? 8a8669010000 }
            // n = 5, score = 300
            //   eb02                 | jmp                 4
            //   33f6                 | xor                 esi, esi
            //   8bce                 | mov                 ecx, esi
            //   e8????????           |                     
            //   8a8669010000         | mov                 al, byte ptr [esi + 0x169]

        $sequence_8 = { 68ac010000 e8???????? 83c404 85c0 7412 }
            // n = 5, score = 300
            //   68ac010000           | push                0x1ac
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   85c0                 | test                eax, eax
            //   7412                 | je                  0x14

        $sequence_9 = { 750a b001 5e 81c490010000 c3 }
            // n = 5, score = 300
            //   750a                 | jne                 0xc
            //   b001                 | mov                 al, 1
            //   5e                   | pop                 esi
            //   81c490010000         | add                 esp, 0x190
            //   c3                   | ret                 

    condition:
        7 of them and filesize < 73728
}