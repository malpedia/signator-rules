rule win_qtbot_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.qtbot."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.qtbot"
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
        $sequence_0 = { 89450c 8d4301 0fb6d8 8a941dfcfeffff 0fb6c2 }
            // n = 5, score = 200
            //   89450c               | mov                 dword ptr [ebp + 0xc], eax
            //   8d4301               | lea                 eax, [ebx + 1]
            //   0fb6d8               | movzx               ebx, al
            //   8a941dfcfeffff       | mov                 dl, byte ptr [ebp + ebx - 0x104]
            //   0fb6c2               | movzx               eax, dl

        $sequence_1 = { 75e9 5b 5d c20400 }
            // n = 4, score = 200
            //   75e9                 | jne                 0xffffffeb
            //   5b                   | pop                 ebx
            //   5d                   | pop                 ebp
            //   c20400               | ret                 4

        $sequence_2 = { 25ffffff00 42 8a1a 84db }
            // n = 4, score = 200
            //   25ffffff00           | and                 eax, 0xffffff
            //   42                   | inc                 edx
            //   8a1a                 | mov                 bl, byte ptr [edx]
            //   84db                 | test                bl, bl

        $sequence_3 = { 8b049a 03c6 50 e8???????? }
            // n = 4, score = 200
            //   8b049a               | mov                 eax, dword ptr [edx + ebx*4]
            //   03c6                 | add                 eax, esi
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_4 = { 33c0 53 8a1a 6bc80d 0fb6c3 83c0d0 }
            // n = 6, score = 200
            //   33c0                 | xor                 eax, eax
            //   53                   | push                ebx
            //   8a1a                 | mov                 bl, byte ptr [edx]
            //   6bc80d               | imul                ecx, eax, 0xd
            //   0fb6c3               | movzx               eax, bl
            //   83c0d0               | add                 eax, -0x30

        $sequence_5 = { 03d6 8b481c 8b4018 03ce }
            // n = 4, score = 200
            //   03d6                 | add                 edx, esi
            //   8b481c               | mov                 ecx, dword ptr [eax + 0x1c]
            //   8b4018               | mov                 eax, dword ptr [eax + 0x18]
            //   03ce                 | add                 ecx, esi

        $sequence_6 = { 40 89450c 83ef01 75b1 8b4510 5f 5e }
            // n = 7, score = 200
            //   40                   | inc                 eax
            //   89450c               | mov                 dword ptr [ebp + 0xc], eax
            //   83ef01               | sub                 edi, 1
            //   75b1                 | jne                 0xffffffb3
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi

        $sequence_7 = { 85ff 7455 8b4510 89450c }
            // n = 4, score = 200
            //   85ff                 | test                edi, edi
            //   7455                 | je                  0x57
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]
            //   89450c               | mov                 dword ptr [ebp + 0xc], eax

        $sequence_8 = { 894dfc eb0e 8b14957c300010 49 0fafd1 0155fc }
            // n = 6, score = 100
            //   894dfc               | mov                 dword ptr [ebp - 4], ecx
            //   eb0e                 | jmp                 0x10
            //   8b14957c300010       | mov                 edx, dword ptr [edx*4 + 0x1000307c]
            //   49                   | dec                 ecx
            //   0fafd1               | imul                edx, ecx
            //   0155fc               | add                 dword ptr [ebp - 4], edx

        $sequence_9 = { 8bd8 8d7e08 7504 8b2f eb02 }
            // n = 5, score = 100
            //   8bd8                 | mov                 ebx, eax
            //   8d7e08               | lea                 edi, [esi + 8]
            //   7504                 | jne                 6
            //   8b2f                 | mov                 ebp, dword ptr [edi]
            //   eb02                 | jmp                 4

        $sequence_10 = { 0fb6805a210010 ff2485f6200010 8b8614080000 3b45f4 7e03 8945f4 8365fc00 }
            // n = 7, score = 100
            //   0fb6805a210010       | movzx               eax, byte ptr [eax + 0x1000215a]
            //   ff2485f6200010       | jmp                 dword ptr [eax*4 + 0x100020f6]
            //   8b8614080000         | mov                 eax, dword ptr [esi + 0x814]
            //   3b45f4               | cmp                 eax, dword ptr [ebp - 0xc]
            //   7e03                 | jle                 5
            //   8945f4               | mov                 dword ptr [ebp - 0xc], eax
            //   8365fc00             | and                 dword ptr [ebp - 4], 0

        $sequence_11 = { 6a00 ff15???????? 833e05 7521 6a10 6a40 ff15???????? }
            // n = 7, score = 100
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   833e05               | cmp                 dword ptr [esi], 5
            //   7521                 | jne                 0x23
            //   6a10                 | push                0x10
            //   6a40                 | push                0x40
            //   ff15????????         |                     

        $sequence_12 = { 8db720080000 833e00 751e 837efcff 7518 8b46f8 8b04855c300010 }
            // n = 7, score = 100
            //   8db720080000         | lea                 esi, [edi + 0x820]
            //   833e00               | cmp                 dword ptr [esi], 0
            //   751e                 | jne                 0x20
            //   837efcff             | cmp                 dword ptr [esi - 4], -1
            //   7518                 | jne                 0x1a
            //   8b46f8               | mov                 eax, dword ptr [esi - 8]
            //   8b04855c300010       | mov                 eax, dword ptr [eax*4 + 0x1000305c]

        $sequence_13 = { 8b46f8 834de4ff 49 c745e8ff000000 8b3c857c300010 }
            // n = 5, score = 100
            //   8b46f8               | mov                 eax, dword ptr [esi - 8]
            //   834de4ff             | or                  dword ptr [ebp - 0x1c], 0xffffffff
            //   49                   | dec                 ecx
            //   c745e8ff000000       | mov                 dword ptr [ebp - 0x18], 0xff
            //   8b3c857c300010       | mov                 edi, dword ptr [eax*4 + 0x1000307c]

        $sequence_14 = { 33c0 8b7df4 8b0c855c300010 c1e705 33d2 03fe }
            // n = 6, score = 100
            //   33c0                 | xor                 eax, eax
            //   8b7df4               | mov                 edi, dword ptr [ebp - 0xc]
            //   8b0c855c300010       | mov                 ecx, dword ptr [eax*4 + 0x1000305c]
            //   c1e705               | shl                 edi, 5
            //   33d2                 | xor                 edx, edx
            //   03fe                 | add                 edi, esi

        $sequence_15 = { e8???????? 59 837e04ff 8bd8 8d7e08 }
            // n = 5, score = 100
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   837e04ff             | cmp                 dword ptr [esi + 4], -1
            //   8bd8                 | mov                 ebx, eax
            //   8d7e08               | lea                 edi, [esi + 8]

    condition:
        7 of them and filesize < 57344
}