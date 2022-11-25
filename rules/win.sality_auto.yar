rule win_sality_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.sality."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.sality"
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
        $sequence_0 = { 02040a 8845fc 8b4dfc 81e1ff000000 }
            // n = 4, score = 400
            //   02040a               | add                 al, byte ptr [edx + ecx]
            //   8845fc               | mov                 byte ptr [ebp - 4], al
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   81e1ff000000         | and                 ecx, 0xff

        $sequence_1 = { 0302 50 6a00 e8???????? }
            // n = 4, score = 400
            //   0302                 | add                 eax, dword ptr [edx]
            //   50                   | push                eax
            //   6a00                 | push                0
            //   e8????????           |                     

        $sequence_2 = { 0255fc 8855ec 8b45ec 25ff000000 }
            // n = 4, score = 400
            //   0255fc               | add                 dl, byte ptr [ebp - 4]
            //   8855ec               | mov                 byte ptr [ebp - 0x14], dl
            //   8b45ec               | mov                 eax, dword ptr [ebp - 0x14]
            //   25ff000000           | and                 eax, 0xff

        $sequence_3 = { 02c8 884dec 8b55f0 83c201 }
            // n = 4, score = 400
            //   02c8                 | add                 cl, al
            //   884dec               | mov                 byte ptr [ebp - 0x14], cl
            //   8b55f0               | mov                 edx, dword ptr [ebp - 0x10]
            //   83c201               | add                 edx, 1

        $sequence_4 = { 0311 52 6878563412 e8???????? }
            // n = 4, score = 400
            //   0311                 | add                 edx, dword ptr [ecx]
            //   52                   | push                edx
            //   6878563412           | push                0x12345678
            //   e8????????           |                     

        $sequence_5 = { 33c0 eb14 8b450c 83e801 89450c }
            // n = 5, score = 400
            //   33c0                 | xor                 eax, eax
            //   eb14                 | jmp                 0x16
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   83e801               | sub                 eax, 1
            //   89450c               | mov                 dword ptr [ebp + 0xc], eax

        $sequence_6 = { 0302 50 6878563412 e8???????? }
            // n = 4, score = 400
            //   0302                 | add                 eax, dword ptr [edx]
            //   50                   | push                eax
            //   6878563412           | push                0x12345678
            //   e8????????           |                     

        $sequence_7 = { 0302 8945fc 8b4d10 8b55fc }
            // n = 4, score = 400
            //   0302                 | add                 eax, dword ptr [edx]
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   8b4d10               | mov                 ecx, dword ptr [ebp + 0x10]
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]

        $sequence_8 = { 7513 8bc2 83e804 8b00 8906 }
            // n = 5, score = 200
            //   7513                 | jne                 0x15
            //   8bc2                 | mov                 eax, edx
            //   83e804               | sub                 eax, 4
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   8906                 | mov                 dword ptr [esi], eax

        $sequence_9 = { 52 50 ff9539154000 58 6a00 }
            // n = 5, score = 200
            //   52                   | push                edx
            //   50                   | push                eax
            //   ff9539154000         | call                dword ptr [ebp + 0x401539]
            //   58                   | pop                 eax
            //   6a00                 | push                0

        $sequence_10 = { 8b4510 ff35???????? 8f80b8000000 ff35???????? 8f80c4000000 ff35???????? }
            // n = 6, score = 200
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]
            //   ff35????????         |                     
            //   8f80b8000000         | pop                 dword ptr [eax + 0xb8]
            //   ff35????????         |                     
            //   8f80c4000000         | pop                 dword ptr [eax + 0xc4]
            //   ff35????????         |                     

        $sequence_11 = { 59 83c304 40 3b4218 75e2 3b4218 7502 }
            // n = 7, score = 200
            //   59                   | pop                 ecx
            //   83c304               | add                 ebx, 4
            //   40                   | inc                 eax
            //   3b4218               | cmp                 eax, dword ptr [edx + 0x18]
            //   75e2                 | jne                 0xffffffe4
            //   3b4218               | cmp                 eax, dword ptr [edx + 0x18]
            //   7502                 | jne                 4

        $sequence_12 = { 8920 896804 8d9dba114000 895808 }
            // n = 4, score = 200
            //   8920                 | mov                 dword ptr [eax], esp
            //   896804               | mov                 dword ptr [eax + 4], ebp
            //   8d9dba114000         | lea                 ebx, [ebp + 0x4011ba]
            //   895808               | mov                 dword ptr [eax + 8], ebx

        $sequence_13 = { f7e3 0344240c 03c7 8b00 0344240c eb02 }
            // n = 6, score = 200
            //   f7e3                 | mul                 ebx
            //   0344240c             | add                 eax, dword ptr [esp + 0xc]
            //   03c7                 | add                 eax, edi
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   0344240c             | add                 eax, dword ptr [esp + 0xc]
            //   eb02                 | jmp                 4

        $sequence_14 = { 33c0 64678f060000 83c404 c20800 c8000000 8b4510 }
            // n = 6, score = 200
            //   33c0                 | xor                 eax, eax
            //   64678f060000         | pop                 dword ptr fs:[0]
            //   83c404               | add                 esp, 4
            //   c20800               | ret                 8
            //   c8000000             | enter               0, 0
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]

        $sequence_15 = { 50 ff95bc154000 85c0 7403 }
            // n = 4, score = 200
            //   50                   | push                eax
            //   ff95bc154000         | call                dword ptr [ebp + 0x4015bc]
            //   85c0                 | test                eax, eax
            //   7403                 | je                  5

        $sequence_16 = { 0306 50 8d5604 e8???????? }
            // n = 4, score = 100
            //   0306                 | add                 eax, dword ptr [esi]
            //   50                   | push                eax
            //   8d5604               | lea                 edx, [esi + 4]
            //   e8????????           |                     

        $sequence_17 = { 031e ff7608 ff7604 e8???????? }
            // n = 4, score = 100
            //   031e                 | add                 ebx, dword ptr [esi]
            //   ff7608               | push                dword ptr [esi + 8]
            //   ff7604               | push                dword ptr [esi + 4]
            //   e8????????           |                     

        $sequence_18 = { 0202 7466 0fb77202 8b7a04 }
            // n = 4, score = 100
            //   0202                 | add                 al, byte ptr [edx]
            //   7466                 | je                  0x68
            //   0fb77202             | movzx               esi, word ptr [edx + 2]
            //   8b7a04               | mov                 edi, dword ptr [edx + 4]

        $sequence_19 = { 00fb fb 804880bc 280d???????? }
            // n = 4, score = 100
            //   00fb                 | add                 bl, bh
            //   fb                   | sti                 
            //   804880bc             | or                  byte ptr [eax - 0x80], 0xbc
            //   280d????????         |                     

        $sequence_20 = { 0306 50 8b4e04 8d5608 }
            // n = 4, score = 100
            //   0306                 | add                 eax, dword ptr [esi]
            //   50                   | push                eax
            //   8b4e04               | mov                 ecx, dword ptr [esi + 4]
            //   8d5608               | lea                 edx, [esi + 8]

        $sequence_21 = { 0007 7307 c607ff 8ac1 }
            // n = 4, score = 100
            //   0007                 | add                 byte ptr [edi], al
            //   7307                 | jae                 9
            //   c607ff               | mov                 byte ptr [edi], 0xff
            //   8ac1                 | mov                 al, cl

        $sequence_22 = { 010d???????? 83c004 5f 5e }
            // n = 4, score = 100
            //   010d????????         |                     
            //   83c004               | add                 eax, 4
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi

        $sequence_23 = { 014304 c3 53 56 }
            // n = 4, score = 100
            //   014304               | add                 dword ptr [ebx + 4], eax
            //   c3                   | ret                 
            //   53                   | push                ebx
            //   56                   | push                esi

    condition:
        7 of them and filesize < 1523712
}