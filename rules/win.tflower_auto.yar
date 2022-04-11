rule win_tflower_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.tflower."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.tflower"
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
        $sequence_0 = { 0001 0200 0103 0303 }
            // n = 4, score = 200
            //   0001                 | add                 byte ptr [ecx], al
            //   0200                 | add                 al, byte ptr [eax]
            //   0103                 | add                 dword ptr [ebx], eax
            //   0303                 | add                 eax, dword ptr [ebx]

        $sequence_1 = { 8b3c8dac7c4b00 85ff 0f8588000000 33c0 }
            // n = 4, score = 200
            //   8b3c8dac7c4b00       | mov                 edi, dword ptr [ecx*4 + 0x4b7cac]
            //   85ff                 | test                edi, edi
            //   0f8588000000         | jne                 0x8e
            //   33c0                 | xor                 eax, eax

        $sequence_2 = { 731c 8bc1 83e13f c1f806 6bc930 8b048578515000 }
            // n = 6, score = 200
            //   731c                 | jae                 0x1e
            //   8bc1                 | mov                 eax, ecx
            //   83e13f               | and                 ecx, 0x3f
            //   c1f806               | sar                 eax, 6
            //   6bc930               | imul                ecx, ecx, 0x30
            //   8b048578515000       | mov                 eax, dword ptr [eax*4 + 0x505178]

        $sequence_3 = { 001a 0c05 003c0c 05004e0c05 }
            // n = 4, score = 200
            //   001a                 | add                 byte ptr [edx], bl
            //   0c05                 | or                  al, 5
            //   003c0c               | add                 byte ptr [esp + ecx], bh
            //   05004e0c05           | add                 eax, 0x50c4e00

        $sequence_4 = { 0f84da000000 56 8d442430 50 ff742430 57 ff15???????? }
            // n = 7, score = 200
            //   0f84da000000         | je                  0xe0
            //   56                   | push                esi
            //   8d442430             | lea                 eax, dword ptr [esp + 0x30]
            //   50                   | push                eax
            //   ff742430             | push                dword ptr [esp + 0x30]
            //   57                   | push                edi
            //   ff15????????         |                     

        $sequence_5 = { 33c1 898424d0000000 8b442434 8b0c8520cd4e00 8b442414 894c2438 }
            // n = 6, score = 200
            //   33c1                 | xor                 eax, ecx
            //   898424d0000000       | mov                 dword ptr [esp + 0xd0], eax
            //   8b442434             | mov                 eax, dword ptr [esp + 0x34]
            //   8b0c8520cd4e00       | mov                 ecx, dword ptr [eax*4 + 0x4ecd20]
            //   8b442414             | mov                 eax, dword ptr [esp + 0x14]
            //   894c2438             | mov                 dword ptr [esp + 0x38], ecx

        $sequence_6 = { 0001 7708 00f3 7608 }
            // n = 4, score = 200
            //   0001                 | add                 byte ptr [ecx], al
            //   7708                 | ja                  0xa
            //   00f3                 | add                 bl, dh
            //   7608                 | jbe                 0xa

        $sequence_7 = { 000f 7708 0001 7708 }
            // n = 4, score = 200
            //   000f                 | add                 byte ptr [edi], cl
            //   7708                 | ja                  0xa
            //   0001                 | add                 byte ptr [ecx], al
            //   7708                 | ja                  0xa

        $sequence_8 = { 83f801 755f 8d442450 50 56 ff742420 }
            // n = 6, score = 200
            //   83f801               | cmp                 eax, 1
            //   755f                 | jne                 0x61
            //   8d442450             | lea                 eax, dword ptr [esp + 0x50]
            //   50                   | push                eax
            //   56                   | push                esi
            //   ff742420             | push                dword ptr [esp + 0x20]

        $sequence_9 = { 0010 740b 0021 740b }
            // n = 4, score = 200
            //   0010                 | add                 byte ptr [eax], dl
            //   740b                 | je                  0xd
            //   0021                 | add                 byte ptr [ecx], ah
            //   740b                 | je                  0xd

        $sequence_10 = { c1e908 0fb6c9 33348520e54e00 8bc6 }
            // n = 4, score = 200
            //   c1e908               | shr                 ecx, 8
            //   0fb6c9               | movzx               ecx, cl
            //   33348520e54e00       | xor                 esi, dword ptr [eax*4 + 0x4ee520]
            //   8bc6                 | mov                 eax, esi

        $sequence_11 = { 85c0 747c 8b442434 85c0 7474 03c0 }
            // n = 6, score = 200
            //   85c0                 | test                eax, eax
            //   747c                 | je                  0x7e
            //   8b442434             | mov                 eax, dword ptr [esp + 0x34]
            //   85c0                 | test                eax, eax
            //   7474                 | je                  0x76
            //   03c0                 | add                 eax, eax

        $sequence_12 = { 000b 8605???????? 007885 0500788605 }
            // n = 4, score = 200
            //   000b                 | add                 byte ptr [ebx], cl
            //   8605????????         |                     
            //   007885               | add                 byte ptr [eax - 0x7b], bh
            //   0500788605           | add                 eax, 0x5867800

        $sequence_13 = { 0002 7408 00f7 7308 }
            // n = 4, score = 200
            //   0002                 | add                 byte ptr [edx], al
            //   7408                 | je                  0xa
            //   00f7                 | add                 bh, dh
            //   7308                 | jae                 0xa

        $sequence_14 = { 330c85c0fe4e00 0fb6c3 330c85c0fa4e00 8bc6 }
            // n = 4, score = 200
            //   330c85c0fe4e00       | xor                 ecx, dword ptr [eax*4 + 0x4efec0]
            //   0fb6c3               | movzx               eax, bl
            //   330c85c0fa4e00       | xor                 ecx, dword ptr [eax*4 + 0x4efac0]
            //   8bc6                 | mov                 eax, esi

        $sequence_15 = { 0008 7408 0002 7408 }
            // n = 4, score = 200
            //   0008                 | add                 byte ptr [eax], cl
            //   7408                 | je                  0xa
            //   0002                 | add                 byte ptr [edx], al
            //   7408                 | je                  0xa

    condition:
        7 of them and filesize < 6578176
}